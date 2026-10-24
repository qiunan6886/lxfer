// lxfer v1.0 —— 局域网换机助手（带界面）
//
// 无参数运行 = 打开图形界面（本地内置 HTTP 服务 + Edge app 窗口）
// 带参数运行 = 命令行模式（recv / send / --help），等同 v0.1
//
// 图形界面的设计目标（对标三星 Smart Switch）：
//   · 首页两张卡片：发送数据 / 接收数据
//   · 接收端：6 位配对码 + 保存位置选择（原生文件夹对话框）
//   · 发送端：自动发现设备 + 配对码 + 整盘/文件夹选择
//   · 传输中：双设备连线动画 + 大圆环进度 + 速度/剩余时间
//   · 完成：校验结果 + 报告路径 + 打开文件夹
//
// 技术选择：GUI 用内嵌 HTML/CSS（交互动画好写、效果接近原生 App），
// 由本进程起一个只监听 127.0.0.1 的 HTTP 服务，再用 Edge 的 --app 模式
// 打开一个无地址栏的窗口。整个过程零第三方依赖。

// v1.2 起协议升级为批量提交，两端必须使用同一版本（命令行模式已移除）

#![allow(dead_code)]

use std::env;
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const XFER_PORT_DEFAULT: u16 = 8787;
const DISCOVER_PORT: u16 = 8788;
const BUFSZ: usize = 1024 * 1024;
const CHUNK: usize = 4 * 1024 * 1024;
const BATCH_FILES: usize = 128;
const BATCH_BYTES: u64 = 32 * 1024 * 1024;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const UI_HTML: &str = include_str!("ui.html");

// ---------- Windows API ----------
#[link(name = "kernel32")]
extern "system" {
    fn SetConsoleOutputCP(cp: u32) -> i32;
    fn SetConsoleCP(cp: u32) -> i32;
    fn GetLogicalDrives() -> u32;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn GetDiskFreeSpaceExW(
        dir: *const u16,
        free_to_caller: *mut u64,
        total: *mut u64,
        free_total: *mut u64,
    ) -> i32;
    fn GetVolumeInformationW(
        root: *const u16,
        label: *mut u16,
        label_size: u32,
        serial: *mut u32,
        max_comp: *mut u32,
        flags: *mut u32,
        fsname: *mut u16,
        fsname_size: u32,
    ) -> i32;
    fn GetConsoleWindow() -> *mut std::ffi::c_void;
}

#[link(name = "user32")]
extern "system" {
    fn ShowWindow(hwnd: *mut std::ffi::c_void, cmd: i32) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------- 数据结构 ----------
#[derive(Clone)]
struct Drive {
    letter: String,
    #[allow(dead_code)]
    label: String,
    used: u64,
    free: u64,
    #[allow(dead_code)]
    total: u64,
}

#[derive(Clone)]
struct Src {
    path: String,
    size: Option<u64>,
    scanning: bool,
    is_file: bool,
}

#[derive(Clone)]
struct Dev {
    name: String,
    ip: String,
    port: u16,
}

#[derive(Clone, Default)]
struct Prog {
    files_done: u64,
    files_total: u64,
    bytes_done: u64,
    bytes_total: u64,
    current: String,
    speed: f64,
    eta: u64,
    workers: u32,
}

#[derive(Clone, Default)]
struct Res {
    copied: u64,
    skipped: u64,
    failed: u64,
    bytes: u64,
    elapsed: f64,
    avg_speed: f64,
    report: String,
    dest: String,
    failed_list: Vec<(String, String)>,
}

#[derive(Clone)]
struct Ui {
    mode: String,  // home | recv | send
    phase: String, // idle | transferring | done | error
    code: String,
    peer: String,
    ip: String,
    port: u16,
    dest: String,
    dest_free: Option<u64>,
    drives: Vec<Drive>,
    srcs: Vec<Src>,
    devices: Vec<Dev>,
    prog: Prog,
    result: Option<Res>,
    error: String,
    message: String,
    secure: bool,
}

impl Default for Ui {
    fn default() -> Self {
        Ui {
            mode: "home".into(),
            phase: "idle".into(),
            code: String::new(),
            peer: String::new(),
            ip: String::new(),
            port: XFER_PORT_DEFAULT,
            dest: String::new(),
            dest_free: None,
            drives: Vec::new(),
            srcs: Vec::new(),
            devices: Vec::new(),
            prog: Prog::default(),
            result: None,
            error: String::new(),
            message: String::new(),
            secure: false,
        }
    }
}

// ---------- 并行任务（多连接共享一个 job，支持断线重连） ----------
enum JobRole {
    Created,
    Joined,
    Busy,
}

struct Job {
    id: String,
    peer: SocketAddr,
    workers: u32,
    done: Vec<bool>,
    planned: Vec<bool>,
    files_total: u64,
    bytes_total: u64,
    copied: u64,
    skipped: u64,
    failed: u64,
    bytes: u64,
    prog_files: u64,
    prog_bytes: u64,
    failed_list: Vec<(String, String)>,
    errors: Vec<String>,
    started: Instant,
    last_change: Instant,
    dest: PathBuf,
}

fn job_create(state: &Arc<AppState>, id: &str, peer: &SocketAddr, workers: u32, dest: PathBuf) -> JobRole {
    {
        let lj = state.last_job.lock().unwrap();
        if !lj.is_empty() && lj.as_str() == id {
            return JobRole::Busy;
        }
    }
    let mut jl = state.job.lock().unwrap();
    if let Some(j) = jl.as_ref() {
        if j.id != id {
            return JobRole::Busy;
        }
        return JobRole::Joined;
    }
    *jl = Some(Job {
        id: id.to_string(),
        peer: *peer,
        workers,
        done: vec![false; workers as usize],
        planned: vec![false; workers as usize],
        files_total: 0,
        bytes_total: 0,
        copied: 0,
        skipped: 0,
        failed: 0,
        bytes: 0,
        prog_files: 0,
        prog_bytes: 0,
        failed_list: Vec::new(),
        errors: Vec::new(),
        started: Instant::now(),
        last_change: Instant::now(),
        dest,
    });
    state.running.store(true, Ordering::SeqCst);
    state.cancel.store(false, Ordering::SeqCst);
    JobRole::Created
}

fn job_plan(state: &Arc<AppState>, id: &str, widx: u32, files: u64, bytes: u64) {
    let mut jl = state.job.lock().unwrap();
    if let Some(j) = jl.as_mut() {
        if j.id == id {
            let i = widx as usize;
            if i < j.planned.len() && !j.planned[i] {
                j.planned[i] = true;
                j.files_total += files;
                j.bytes_total += bytes;
            }
            j.last_change = Instant::now();
        }
    }
}

fn job_push(state: &Arc<AppState>, id: &str, add_files: u64, add_bytes: u64) -> Option<(u64, u64, u64, u64, f64)> {
    let mut jl = state.job.lock().unwrap();
    let j = match jl.as_mut() {
        Some(j) if j.id == id => j,
        _ => return None,
    };
    j.prog_files += add_files;
    j.prog_bytes += add_bytes;
    if add_files > 0 || add_bytes > 0 {
        j.last_change = Instant::now();
    }
    let el = j.started.elapsed().as_secs_f64().max(0.001);
    Some((j.prog_files, j.prog_bytes, j.files_total, j.bytes_total, el))
}

fn ui_from_job(state: &Arc<AppState>, id: &str, add_files: u64, add_bytes: u64, cur: &str) {
    if let Some((pf, pb, ft, bt, el)) = job_push(state, id, add_files, add_bytes) {
        let mut u = state.lock();
        if u.phase != "transferring" {
            return;
        }
        u.prog.files_done = pf;
        u.prog.bytes_done = pb;
        u.prog.files_total = ft;
        u.prog.bytes_total = bt;
        u.prog.current = cur.to_string();
        u.prog.speed = pb as f64 / el;
        u.prog.eta = if u.prog.speed > 1.0 && bt > pb {
            ((bt - pb) as f64 / u.prog.speed) as u64
        } else {
            0
        };
    }
}

fn job_add_result(state: &Arc<AppState>, id: &str, copied: u64, skipped: u64, failed: u64, bytes: u64, list: Vec<(String, String)>) {
    let mut jl = state.job.lock().unwrap();
    if let Some(j) = jl.as_mut() {
        if j.id == id {
            j.copied += copied;
            j.skipped += skipped;
            j.failed += failed;
            j.bytes += bytes;
            j.failed_list.extend(list);
        }
    }
}

fn job_worker_done(state: &Arc<AppState>, id: &str, widx: u32, ok: bool, err: Option<String>) {
    let mut fin: Option<Job> = None;
    {
        let mut jl = state.job.lock().unwrap();
        if let Some(j) = jl.as_mut() {
            if j.id == id {
                if let Some(e) = err {
                    j.errors.push(e);
                }
                if ok {
                    if let Some(slot) = j.done.get_mut(widx as usize) {
                        *slot = true;
                    }
                }
                j.last_change = Instant::now();
                if j.done.iter().all(|&d| d) {
                    fin = jl.take();
                }
            }
        }
    }
    if let Some(j) = fin {
        finalize_job(state, j);
    }
}
fn job_apply_mask(state: &Arc<AppState>, id: &str, mask: u32) {
    let mut fin: Option<Job> = None;
    {
        let mut jl = state.job.lock().unwrap();
        if let Some(j) = jl.as_mut() {
            if j.id == id {
                for i in 0..j.done.len().min(32) {
                    if mask & (1 << i) != 0 {
                        j.done[i] = true;
                    }
                }
                j.last_change = Instant::now();
                if j.done.iter().all(|&d| d) {
                    fin = jl.take();
                }
            }
        }
    }
    if let Some(j) = fin {
        finalize_job(state, j);
    }
}
fn job_apply_info(state: &Arc<AppState>, id: &str, info: &str) {
    let mut updates: Vec<(usize, u64, u64, u64, u64)> = Vec::new();
    for part in info.split(';') {
        let f: Vec<&str> = part.split(',').collect();
        if f.len() < 5 {
            continue;
        }
        if let (Ok(i), Ok(c), Ok(s), Ok(fl), Ok(b)) = (
            f[0].parse::<usize>(),
            f[1].parse::<u64>(),
            f[2].parse::<u64>(),
            f[3].parse::<u64>(),
            f[4].parse::<u64>(),
        ) {
            updates.push((i, c, s, fl, b));
        }
    }
    if updates.is_empty() {
        return;
    }
    let mut fin: Option<Job> = None;
    {
        let mut jl = state.job.lock().unwrap();
        if let Some(j) = jl.as_mut() {
            if j.id == id {
                for (i, c, s, fl, b) in updates {
                    if i < j.done.len() && !j.done[i] {
                        j.done[i] = true;
                        j.copied += c;
                        j.skipped += s;
                        j.failed += fl;
                        j.bytes += b;
                    }
                }
                j.last_change = Instant::now();
                if j.done.iter().all(|&d| d) {
                    fin = jl.take();
                }
            }
        }
    }
    if let Some(j) = fin {
        finalize_job(state, j);
    }
}

fn finalize_job(state: &Arc<AppState>, mut j: Job) {
    let cancelled = state.cancel.load(Ordering::SeqCst);
    let elapsed = j.started.elapsed().as_secs_f64();
    for e in &j.errors {
        j.failed_list.push(("（连接异常）".to_string(), e.clone()));
    }
    let mut st = Res {
        copied: j.copied,
        skipped: j.skipped,
        failed: j.failed + j.errors.len() as u64,
        bytes: j.bytes,
        elapsed,
        avg_speed: if elapsed > 0.0 { j.bytes as f64 / elapsed } else { 0.0 },
        report: String::new(),
        dest: j.dest.to_string_lossy().to_string(),
        failed_list: j.failed_list.clone(),
    };
    if !cancelled {
        st.report = write_report(&j.dest, &j.peer, &st).map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
    }
    let mut u = state.lock();
    u.prog.files_done = u.prog.files_total;
    u.prog.bytes_done = u.prog.bytes_total;
    u.prog.current = String::new();
    if cancelled {
        u.phase = "idle".into();
        u.message = "已取消，重新开始会从断点继续".into();
    } else {
        u.phase = "done".into();
        u.result = Some(st);
        u.message = if j.errors.is_empty() { String::new() } else { "部分连接异常，已完成部分见报告".into() };
    }
    drop(u);
    *state.last_job.lock().unwrap() = j.id.clone();
    state.running.store(false, Ordering::SeqCst);
}

fn drive_free(p: &Path) -> Option<u64> {
    let s = p.to_string_lossy().to_string();
    let c = s.chars().next()?;
    let up = c.to_ascii_uppercase();
    list_drives().iter().find(|d| d.letter.starts_with(up)).map(|d| d.free)
}
struct AppState {
    ui: Mutex<Ui>,
    running: AtomicBool,
    cancel: AtomicBool,
    xfer_port: u16,
    last_req_ms: std::sync::atomic::AtomicU64,
    job: Mutex<Option<Job>>,
    last_job: Mutex<String>,
}

impl AppState {
    fn lock(&self) -> std::sync::MutexGuard<'_, Ui> {
        self.ui.lock().unwrap()
    }
    fn message(&self, m: &str) {
        self.lock().message = m.to_string();
    }
}

// ---------- 通用小工具 ----------
fn now_millis() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
fn mtime_of(md: &fs::Metadata) -> u64 {
    md.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)
}
fn set_mtime(f: &File, secs: u64) {
    let t = UNIX_EPOCH + Duration::from_secs(secs);
    let _ = f.set_times(FileTimes::new().set_modified(t));
}
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as i64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
fn fmt_time(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", y, m, d, rem / 3600, (rem % 3600) / 60, rem % 60)
}
fn beijing_now() -> String {
    fmt_time(now_secs() + 8 * 3600)
}
fn local_ip() -> String {
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(a) = s.local_addr() {
                return a.ip().to_string();
            }
        }
    }
    "127.0.0.1".into()
}
fn hostname() -> String {
    env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

// ---------- 协议原语（与 CLI 版一致） ----------
fn crctab() -> [u32; 256] {
    let mut t = [0u32; 256];
    for i in 0..256u32 {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        t[i as usize] = c;
    }
    t
}
fn crc_update(t: &[u32; 256], mut crc: u32, data: &[u8]) -> u32 {
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 16);
    for c in s.chars() {
        match c {
            '\\' => o.push_str("\\\\"),
            '\t' => o.push_str("\\t"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            _ => o.push(c),
        }
    }
    o
}
fn unesc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('\\') => o.push('\\'),
                Some('t') => o.push('\t'),
                Some('n') => o.push('\n'),
                Some('r') => o.push('\r'),
                Some(x) => o.push(x),
                None => {}
            }
        } else {
            o.push(c)
        }
    }
    o
}
fn fields(line: &str) -> Vec<String> {
    line.split('\t').map(unesc).collect()
}
fn read_msg(rd: &mut BufReader<TcpStream>) -> io::Result<String> {
    let mut s = String::new();
    let n = rd.read_line(&mut s)?;
    if n == 0 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "对方已断开连接"));
    }
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    Ok(s)
}
fn put_line(wr: &mut BufWriter<TcpStream>, line: &str) -> io::Result<()> {
    wr.write_all(line.as_bytes())?;
    wr.write_all(b"\n")?;
    Ok(())
}
fn send_line(wr: &mut BufWriter<TcpStream>, line: &str) -> io::Result<()> {
    wr.write_all(line.as_bytes())?;
    wr.write_all(b"\n")?;
    wr.flush()
}

// ---------- 遍历 ----------
#[derive(Clone)]
struct Entry {
    rel: String,
    size: u64,
    mtime: u64,
}
fn should_skip(name: &str) -> bool {
    let l = name.to_lowercase();
    matches!(
        l.as_str(),
        "system volume information"
            | "$recycle.bin"
            | "config.msi"
            | "pagefile.sys"
            | "hiberfil.sys"
            | "swapfile.sys"
            | "dumpstack.log.tmp"
    )
}
fn walk_dir(base: &Path, cur: &Path, dirs: &mut Vec<String>, files: &mut Vec<Entry>) {
    let rd = match fs::read_dir(cur) {
        Ok(r) => r,
        Err(_) => return,
    };
    for e in rd.flatten() {
        let fname = e.file_name().to_string_lossy().to_string();
        if should_skip(&fname) {
            continue;
        }
        let md = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.file_type().is_symlink() {
            continue;
        }
        let p = e.path();
        let rel = match p.strip_prefix(base) {
            Ok(r) => r.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        if md.file_type().is_dir() {
            dirs.push(rel);
            walk_dir(base, &p, dirs, files);
        } else if md.file_type().is_file() {
            files.push(Entry { rel, size: md.len(), mtime: mtime_of(&md) });
        }
    }
}
fn root_name(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    let t = s.trim_end_matches(['\\', '/']).to_string();
    if t.len() == 2 && t.ends_with(':') {
        return t[..1].to_uppercase();
    }
    match Path::new(&t).file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => "root".into(),
    }
}
fn norm_key(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    let mut t = s.replace('/', "\\");
    while t.len() > 3 && t.ends_with('\\') {
        t.pop();
    }
    t.to_lowercase()
}
fn is_same_or_inside(child: &Path, parent: &Path) -> bool {
    let c = norm_key(child);
    let p = norm_key(parent);
    c == p || c.starts_with(&format!("{}\\", p))
}
fn file_root(p: &Path) -> String {
    match p.parent() {
        Some(par) if !par.as_os_str().is_empty() => match par.file_name() {
            Some(n) => n.to_string_lossy().to_string(),
            None => root_name(par),
        },
        _ => root_name(p),
    }
}
fn human_size(n: u64) -> String {
    let f = n as f64;
    if f >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GB", f / 1024.0 / 1024.0 / 1024.0)
    } else if f >= 1024.0 * 1024.0 {
        format!("{:.1} MB", f / 1024.0 / 1024.0)
    } else if f >= 1024.0 {
        format!("{:.1} KB", f / 1024.0)
    } else {
        format!("{} B", n)
    }
}

// ---------- 磁盘 ----------
fn list_drives() -> Vec<Drive> {
    let mask = unsafe { GetLogicalDrives() };
    let mut out = Vec::new();
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let letter = (b'A' + i as u8) as char;
        let root = format!("{}:\\", letter);
        let w = wide(&root);
        let t = unsafe { GetDriveTypeW(w.as_ptr()) };
        if t != 2 && t != 3 {
            continue;
        }
        let mut free_caller = 0u64;
        let mut total = 0u64;
        let mut free_total = 0u64;
        let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free_caller, &mut total, &mut free_total) };
        if ok == 0 {
            continue;
        }
        let mut label_buf = vec![0u16; 128];
        let mut serial = 0u32;
        let mut maxc = 0u32;
        let mut flags = 0u32;
        let mut fsbuf = vec![0u16; 32];
        unsafe {
            GetVolumeInformationW(
                w.as_ptr(),
                label_buf.as_mut_ptr(),
                128,
                &mut serial,
                &mut maxc,
                &mut flags,
                fsbuf.as_mut_ptr(),
                32,
            );
        }
        let label = String::from_utf16_lossy(&label_buf).trim_end_matches('\0').to_string();
        out.push(Drive {
            letter: letter.to_string(),
            label,
            used: total.saturating_sub(free_caller),
            free: free_caller,
            total,
        });
    }
    out
}

// ---------- JSON ----------
fn jstr(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 8);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}
fn state_json(ui: &Ui) -> String {
    let drives: Vec<String> = ui
        .drives
        .iter()
        .map(|d| {
            format!(
                "{{\"letter\":{},\"label\":{},\"used\":{},\"free\":{},\"total\":{}}}",
                jstr(&d.letter),
                jstr(&d.label),
                d.used,
                d.free,
                d.total
            )
        })
        .collect();
    let srcs: Vec<String> = ui
        .srcs
        .iter()
        .map(|s| {
            format!(
                "{{\"path\":{},\"size\":{},\"scanning\":{},\"file\":{}}}",
                jstr(&s.path),
                s.size.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
                s.scanning,
                s.is_file
            )
        })
        .collect();
    let devs: Vec<String> = ui
        .devices
        .iter()
        .map(|d| format!("{{\"name\":{},\"ip\":{},\"port\":{}}}", jstr(&d.name), jstr(&d.ip), d.port))
        .collect();
    let res = match &ui.result {
        None => "null".to_string(),
        Some(r) => {
            let list: Vec<String> = r
                .failed_list
                .iter()
                .map(|(p, x)| format!("[{},{}]", jstr(p), jstr(x)))
                .collect();
            format!(
                "{{\"copied\":{},\"skipped\":{},\"failed\":{},\"bytes\":{},\"elapsed\":{:.1},\"avgSpeed\":{:.1},\"report\":{},\"dest\":{},\"failedList\":[{}]}}",
                r.copied,
                r.skipped,
                r.failed,
                r.bytes,
                r.elapsed,
                r.avg_speed,
                jstr(&r.report),
                jstr(&r.dest),
                list.join(",")
            )
        }
    };
    format!(
        "{{\"mode\":{},\"phase\":{},\"code\":{},\"peer\":{},\"ip\":{},\"port\":{},\"dest\":{},\"destFree\":{},\"drives\":[{}],\"srcs\":[{}],\"devices\":[{}],\"prog\":{{\"filesDone\":{},\"filesTotal\":{},\"bytesDone\":{},\"bytesTotal\":{},\"current\":{},\"speed\":{:.1},\"eta\":{},\"workers\":{}}},\"result\":{},\"error\":{},\"message\":{},\"secure\":{}}}",
        jstr(&ui.mode),
        jstr(&ui.phase),
        jstr(&ui.code),
        jstr(&ui.peer),
        jstr(&ui.ip),
        ui.port,
        jstr(&ui.dest),
        ui.dest_free.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
        drives.join(","),
        srcs.join(","),
        devs.join(","),
        ui.prog.files_done,
        ui.prog.files_total,
        ui.prog.bytes_done,
        ui.prog.bytes_total,
        jstr(&ui.prog.current),
        ui.prog.speed,
        ui.prog.eta,
        ui.prog.workers,
        res,
        jstr(&ui.error),
        jstr(&ui.message),
        ui.secure,
    )
}

// ---------- 进度推送 ----------
fn push_prog(state: &Arc<AppState>, files_done: u64, bytes_done: u64, current: &str, started: Instant) {
    let mut u = state.lock();
    u.prog.files_done = files_done;
    u.prog.bytes_done = bytes_done;
    u.prog.current = current.to_string();
    let secs = started.elapsed().as_secs_f64().max(0.001);
    u.prog.speed = bytes_done as f64 / secs;
    let total = u.prog.bytes_total;
    u.prog.eta = if u.prog.speed > 1.0 && total > bytes_done {
        ((total - bytes_done) as f64 / u.prog.speed) as u64
    } else {
        0
    };
}

// ==================== 加密通道（Windows CNG：ECDH P-256 + AES-256-GCM） ====================
// 用系统自带 bcrypt.dll，不引入任何第三方依赖；握手用 ECDH 协商出会话密钥，
// 之后所有控制消息和数据都走 AES-256-GCM 加密记录（每个连接独立密钥）。

#[repr(C)]
struct BcryptBuffer {
    cb: u32,
    btype: u32,
    pv: *mut std::ffi::c_void,
}
#[repr(C)]
struct BcryptBufferDesc {
    ver: u32,
    count: u32,
    bufs: *mut BcryptBuffer,
}
#[repr(C)]
struct AuthCipherInfo {
    cb_size: u32,
    info_version: u32,
    pb_nonce: *mut u8,
    cb_nonce: u32,
    pb_auth: *mut u8,
    cb_auth: u32,
    pb_tag: *mut u8,
    cb_tag: u32,
    pb_mac: *mut u8,
    cb_mac: u32,
    cb_aad: u32,
    cb_data: u64,
    flags: u32,
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptOpenAlgorithmProvider(ph: *mut Hnd, alg: *const u16, imp: *const u16, flags: u32) -> i32;
    fn BCryptCloseAlgorithmProvider(h: Hnd, flags: u32) -> i32;
    fn BCryptGenerateKeyPair(alg: Hnd, ph: *mut Hnd, len: u32, flags: u32) -> i32;
    fn BCryptFinalizeKeyPair(k: Hnd, flags: u32) -> i32;
    fn BCryptExportKey(k: Hnd, exp: Hnd, blob: *const u16, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> i32;
    fn BCryptImportKeyPair(alg: Hnd, imp: Hnd, blob: *const u16, ph: *mut Hnd, input: *const u8, cb: u32, flags: u32) -> i32;
    fn BCryptSecretAgreement(priv_k: Hnd, pub_k: Hnd, ph: *mut Hnd, flags: u32) -> i32;
    fn BCryptDeriveKey(secret: Hnd, kdf: *const u16, params: *mut BcryptBufferDesc, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> i32;
    fn BCryptDestroySecret(s: Hnd) -> i32;
    fn BCryptDestroyKey(k: Hnd) -> i32;
    fn BCryptSetProperty(obj: Hnd, prop: *const u16, input: *const u8, cb: u32, flags: u32) -> i32;
    fn BCryptGenerateSymmetricKey(alg: Hnd, ph: *mut Hnd, obj: *mut u8, cbobj: u32, secret: *const u8, cb: u32, flags: u32) -> i32;
    fn BCryptEncrypt(k: Hnd, input: *const u8, cb: u32, info: *mut std::ffi::c_void, iv: *mut u8, cbiv: u32, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> i32;
    fn BCryptDecrypt(k: Hnd, input: *const u8, cb: u32, info: *mut std::ffi::c_void, iv: *mut u8, cbiv: u32, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> i32;
}

type Hnd = *mut std::ffi::c_void;

fn u16z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
fn hex_enc(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
fn hex_dec(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

struct Crypto {
    alg_ecdh: Hnd,
    priv_key: Hnd,
    alg_aes: Hnd,
    aes_key: Hnd,
    pub_blob: Vec<u8>,
    send_ctr: u64,
}

impl Drop for Crypto {
    fn drop(&mut self) {
        unsafe {
            if !self.aes_key.is_null() {
                BCryptDestroyKey(self.aes_key);
            }
            if !self.priv_key.is_null() {
                BCryptDestroyKey(self.priv_key);
            }
            if !self.alg_aes.is_null() {
                BCryptCloseAlgorithmProvider(self.alg_aes, 0);
            }
            if !self.alg_ecdh.is_null() {
                BCryptCloseAlgorithmProvider(self.alg_ecdh, 0);
            }
        }
    }
}

impl Crypto {
    fn new() -> Option<Crypto> {
        unsafe {
            let mut alg: Hnd = std::ptr::null_mut();
            if BCryptOpenAlgorithmProvider(&mut alg, u16z("ECDH_P256").as_ptr(), std::ptr::null(), 0) != 0 {
                return None;
            }
            let mut pk: Hnd = std::ptr::null_mut();
            if BCryptGenerateKeyPair(alg, &mut pk, 256, 0) != 0 {
                BCryptCloseAlgorithmProvider(alg, 0);
                return None;
            }
            if BCryptFinalizeKeyPair(pk, 0) != 0 {
                BCryptDestroyKey(pk);
                BCryptCloseAlgorithmProvider(alg, 0);
                return None;
            }
            let mut cap = 0u32;
            let blob_type = u16z("ECCPUBLICBLOB");
            BCryptExportKey(pk, std::ptr::null_mut(), blob_type.as_ptr(), std::ptr::null_mut(), 0, &mut cap, 0);
            if cap == 0 {
                BCryptDestroyKey(pk);
                BCryptCloseAlgorithmProvider(alg, 0);
                return None;
            }
            let mut blob = vec![0u8; cap as usize];
            let mut res = 0u32;
            if BCryptExportKey(pk, std::ptr::null_mut(), blob_type.as_ptr(), blob.as_mut_ptr(), cap, &mut res, 0) != 0 {
                BCryptDestroyKey(pk);
                BCryptCloseAlgorithmProvider(alg, 0);
                return None;
            }
            blob.truncate(res as usize);
            Some(Crypto {
                alg_ecdh: alg,
                priv_key: pk,
                alg_aes: std::ptr::null_mut(),
                aes_key: std::ptr::null_mut(),
                pub_blob: blob,
                send_ctr: 0,
            })
        }
    }

    fn pub_hex(&self) -> String {
        hex_enc(&self.pub_blob)
    }

    fn derive(&mut self, peer_hex: &str, bind: &str) -> bool {
        let peer = match hex_dec(peer_hex) {
            Some(v) if v.len() >= 8 => v,
            _ => return false,
        };
        unsafe {
            let mut pubk: Hnd = std::ptr::null_mut();
            if BCryptImportKeyPair(
                self.alg_ecdh,
                std::ptr::null_mut(),
                u16z("ECCPUBLICBLOB").as_ptr(),
                &mut pubk,
                peer.as_ptr(),
                peer.len() as u32,
                0,
            ) != 0
            {
                return false;
            }
            let mut secret: Hnd = std::ptr::null_mut();
            if BCryptSecretAgreement(self.priv_key, pubk, &mut secret, 0) != 0 {
                BCryptDestroyKey(pubk);
                return false;
            }
            let mut sha = u16z("SHA256");
            let mut bind_bytes = bind.as_bytes().to_vec();
            let mut buf = BcryptBuffer {
                cb: (sha.len() * 2) as u32,
                btype: 0, // KDF_HASH_ALGORITHM
                pv: sha.as_mut_ptr() as *mut std::ffi::c_void,
            };
            let mut buf2 = BcryptBuffer {
                cb: bind_bytes.len() as u32,
                btype: 2, // KDF_SECRET_APPEND：把配对码绑进密钥
                pv: bind_bytes.as_mut_ptr() as *mut std::ffi::c_void,
            };
            let mut bufs = [buf, buf2];
            let mut desc = BcryptBufferDesc { ver: 0, count: 2, bufs: bufs.as_mut_ptr() };
            let mut key = vec![0u8; 32];
            let mut res = 0u32;
            let rc = BCryptDeriveKey(
                secret,
                u16z("HASH").as_ptr(),
                &mut desc,
                key.as_mut_ptr(),
                32,
                &mut res,
                0,
            );
            BCryptDestroySecret(secret);
            BCryptDestroyKey(pubk);
            if rc != 0 || res < 32 {
                return false;
            }
            let mut alg: Hnd = std::ptr::null_mut();
            if BCryptOpenAlgorithmProvider(&mut alg, u16z("AES").as_ptr(), std::ptr::null(), 0) != 0 {
                return false;
            }
            let mode = u16z("ChainingModeGCM");
            if BCryptSetProperty(
                alg,
                u16z("ChainingMode").as_ptr(),
                mode.as_ptr() as *const u8,
                (mode.len() * 2) as u32,
                0,
            ) != 0
            {
                BCryptCloseAlgorithmProvider(alg, 0);
                return false;
            }
            let mut k: Hnd = std::ptr::null_mut();
            if BCryptGenerateSymmetricKey(alg, &mut k, std::ptr::null_mut(), 0, key.as_ptr(), 32, 0) != 0 {
                BCryptCloseAlgorithmProvider(alg, 0);
                return false;
            }
            self.alg_aes = alg;
            self.aes_key = k;
            true
        }
    }

    /// 返回 payload = [ctr 8 字节][密文][tag 16 字节]
    fn encrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let mut nonce = [0u8; 12];
            let c = self.send_ctr;
            self.send_ctr += 1;
            nonce[4..12].copy_from_slice(&c.to_be_bytes());
            let mut tag = [0u8; 16];
            let mut info = AuthCipherInfo {
                cb_size: std::mem::size_of::<AuthCipherInfo>() as u32,
                info_version: 1,
                pb_nonce: nonce.as_mut_ptr(),
                cb_nonce: 12,
                pb_auth: std::ptr::null_mut(),
                cb_auth: 0,
                pb_tag: tag.as_mut_ptr(),
                cb_tag: 16,
                pb_mac: std::ptr::null_mut(),
                cb_mac: 0,
                cb_aad: 0,
                cb_data: 0,
                flags: 0,
            };
            let mut out = vec![0u8; data.len() + 8 + 16];
            out[0..8].copy_from_slice(&c.to_be_bytes());
            let mut written = 0u32;
            let rc = BCryptEncrypt(
                self.aes_key,
                data.as_ptr(),
                data.len() as u32,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::ptr::null_mut(),
                0,
                out[8..8 + data.len()].as_mut_ptr(),
                data.len() as u32,
                &mut written,
                0,
            );
            if rc != 0 || written as usize != data.len() {
                return None;
            }
            out[8 + data.len()..].copy_from_slice(&tag);
            Some(out)
        }
    }

    fn decrypt(&self, payload: &[u8]) -> Option<Vec<u8>> {
        if payload.len() < 24 {
            return None;
        }
        let ctr = u64::from_be_bytes([payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7]]);
        let ct_len = payload.len() - 8 - 16;
        let ct = &payload[8..8 + ct_len];
        let mut tag = payload[8 + ct_len..].to_vec();
        unsafe {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&ctr.to_be_bytes());
            let mut info = AuthCipherInfo {
                cb_size: std::mem::size_of::<AuthCipherInfo>() as u32,
                info_version: 1,
                pb_nonce: nonce.as_mut_ptr(),
                cb_nonce: 12,
                pb_auth: std::ptr::null_mut(),
                cb_auth: 0,
                pb_tag: tag.as_mut_ptr(),
                cb_tag: 16,
                pb_mac: std::ptr::null_mut(),
                cb_mac: 0,
                cb_aad: 0,
                cb_data: 0,
                flags: 0,
            };
            let mut out = vec![0u8; ct_len];
            let mut written = 0u32;
            let rc = BCryptDecrypt(
                self.aes_key,
                ct.as_ptr(),
                ct_len as u32,
                &mut info as *mut _ as *mut std::ffi::c_void,
                std::ptr::null_mut(),
                0,
                out.as_mut_ptr(),
                ct_len as u32,
                &mut written,
                0,
            );
            if rc != 0 || written as usize != ct_len {
                return None;
            }
            Some(out)
        }
    }
}

// ---------- 连接（自动加密 / 明文降级） ----------
struct Conn {
    rd: BufReader<TcpStream>,
    wr: BufWriter<TcpStream>,
    crypto: Option<Crypto>,
    linebuf: Vec<u8>,
}

impl Conn {
    fn new(stream: &TcpStream) -> io::Result<Conn> {
        Ok(Conn {
            rd: BufReader::with_capacity(BUFSZ, stream.try_clone()?),
            wr: BufWriter::with_capacity(BUFSZ, stream.try_clone()?),
            crypto: None,
            linebuf: Vec::new(),
        })
    }
    fn secure(&self) -> bool {
        self.crypto.is_some()
    }
    fn set_crypto(&mut self, c: Crypto) {
        self.crypto = Some(c);
    }
    fn put_line(&mut self, line: &str) -> io::Result<()> {
        match self.crypto.as_mut() {
            Some(c) => {
                let mut payload = line.as_bytes().to_vec();
                payload.push(b'\n');
                let rec = c.encrypt(&payload).ok_or_else(|| io::Error::new(io::ErrorKind::Other, "加密失败"))?;
                self.wr.write_all(&(rec.len() as u32).to_be_bytes())?;
                self.wr.write_all(&rec)?;
            }
            None => {
                self.wr.write_all(line.as_bytes())?;
                self.wr.write_all(b"\n")?;
            }
        }
        Ok(())
    }
    fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.put_line(line)?;
        self.wr.flush()
    }
    fn flush(&mut self) -> io::Result<()> {
        self.wr.flush()
    }
    fn read_record(&mut self) -> io::Result<Vec<u8>> {
        let mut lb = [0u8; 4];
        self.rd.read_exact(&mut lb)?;
        let n = u32::from_be_bytes(lb) as usize;
        if n == 0 || n > 16 * 1024 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "记录长度异常"));
        }
        let mut v = vec![0u8; n];
        self.rd.read_exact(&mut v)?;
        Ok(v)
    }
    fn read_msg(&mut self) -> io::Result<String> {
        loop {
            if let Some(pos) = self.linebuf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.linebuf.drain(..=pos).collect();
                let s = String::from_utf8_lossy(&line[..line.len() - 1]).to_string();
                return Ok(s.trim_end_matches('\r').to_string());
            }
            if self.crypto.is_some() {
                let rec = self.read_record()?;
                let pt = match self.crypto.as_ref() {
                    Some(c) => c.decrypt(&rec),
                    None => None,
                };
                match pt {
                    Some(p) => self.linebuf.extend_from_slice(&p),
                    None => return Err(io::Error::new(io::ErrorKind::InvalidData, "解密失败")),
                }
            } else {
                let mut tmp = Vec::new();
                let n = self.rd.read_until(b'\n', &mut tmp)?;
                if n == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "对方已断开连接"));
                }
                self.linebuf.extend_from_slice(&tmp);
            }
        }
    }
    fn write_frame(&mut self, data: &[u8]) -> io::Result<()> {
        match self.crypto.as_mut() {
            Some(c) => {
                let rec = c.encrypt(data).ok_or_else(|| io::Error::new(io::ErrorKind::Other, "加密失败"))?;
                self.wr.write_all(&(rec.len() as u32).to_be_bytes())?;
                self.wr.write_all(&rec)?;
            }
            None => {
                self.wr.write_all(&(data.len() as u32).to_be_bytes())?;
                self.wr.write_all(data)?;
            }
        }
        Ok(())
    }
    fn read_frame(&mut self, out: &mut Vec<u8>) -> io::Result<bool> {
        if self.crypto.is_some() {
            let rec = self.read_record()?;
            let pt = match self.crypto.as_ref() {
                Some(c) => c.decrypt(&rec),
                None => None,
            };
            match pt {
                Some(v) => {
                    if v.is_empty() {
                        Ok(false)
                    } else {
                        out.clear();
                        out.extend_from_slice(&v);
                        Ok(true)
                    }
                }
                None => Err(io::Error::new(io::ErrorKind::InvalidData, "数据解密失败")),
            }
        } else {
            let mut lb = [0u8; 4];
            self.rd.read_exact(&mut lb)?;
            let n = u32::from_be_bytes(lb) as usize;
            if n == 0 {
                return Ok(false);
            }
            if n > 8 * 1024 * 1024 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "帧长度异常"));
            }
            out.clear();
            out.resize(n, 0);
            self.rd.read_exact(out)?;
            Ok(true)
        }
    }
}
// ---------- 传输引擎：接收 ----------
fn recv_session(state: Arc<AppState>, stream: TcpStream, peer: SocketAddr, code_in: String, dest_ui: PathBuf) {
    let t = crctab();
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
    let mut conn = match Conn::new(&stream) {
        Ok(c) => c,
        Err(_) => return,
    };

    let line = match conn.read_msg() {
        Ok(l) => l,
        Err(_) => return,
    };
    let f = fields(&line);
    if f.len() < 8 || f[0] != "HELLO2" {
        let _ = conn.send_line("DENY\t协议不匹配，请两台电脑都换成本次的新 lxfer.exe");
        return;
    }
    if f[1] != code_in {
        let _ = conn.send_line("DENY\t配对码错误");
        state.message("有设备尝试连接但配对码不正确，已拒绝");
        return;
    }
    let job_id = f[3].clone();
    let widx: u32 = f[4].parse().unwrap_or(0);
    let count: u32 = f[5].parse().unwrap_or(1).max(1);
    let peer_pub = f[6].clone();
    let total_bytes: u64 = f[7].parse().unwrap_or(0);
    let done_mask: u32 = f.get(8).and_then(|s| s.parse().ok()).unwrap_or(0);
    let done_info: String = f.get(9).cloned().unwrap_or_default();

    // 磁盘空间预检：不够就直接拒绝，别传一半撑爆
    if total_bytes > 0 {
        if let Some(free) = drive_free(&dest_ui) {
            if total_bytes > free {
                let _ = conn.send_line(&format!(
                    "DENY\t目标磁盘空间不足：需要 {}，{} 只剩 {}",
                    human_size(total_bytes),
                    dest_ui.to_string_lossy(),
                    human_size(free)
                ));
                return;
            }
        }
    }

    match job_create(&state, &job_id, &peer, count, dest_ui.clone()) {
        JobRole::Busy => {
            let _ = conn.send_line("DENY\t接收端正在处理其他传输任务");
            return;
        }
        JobRole::Created => {
            let mut u = state.lock();
            u.phase = "transferring".into();
            u.result = None;
            u.error.clear();
            u.prog = Prog::default();
            u.prog.workers = count;
        }
        JobRole::Joined => {}
    }
    if !done_info.is_empty() {
        job_apply_info(&state, &job_id, &done_info);
    }
    if done_mask != 0 {
        job_apply_mask(&state, &job_id, done_mask);
    }

    // 加密握手（ECDH 协商失败则降级明文）
    let mut crypto = Crypto::new();
    let mut enc = false;
    if let Some(c) = crypto.as_mut() {
        if c.derive(&peer_pub, &code_in) {
            enc = true;
        }
    }
    let pub_hex = match crypto.as_ref() {
        Some(c) => c.pub_hex(),
        None => String::new(),
    };
    if conn.send_line(&format!("WELCOME\t{}\t{}", if enc { 1 } else { 0 }, pub_hex)).is_err() {
        job_worker_done(&state, &job_id, widx, false, Some("握手失败".into()));
        return;
    }
    if enc {
        if let Some(c) = crypto.take() {
            conn.set_crypto(c);
        }
    } else {
        crypto = None;
        state.message("系统加密服务不可用，本次传输降级为明文");
    }
    {
        let mut u = state.lock();
        u.secure = enc;
    }

    let mut copied = 0u64;
    let mut skipped = 0u64;
    let mut failed = 0u64;
    let mut bytes = 0u64;
    let mut failed_list: Vec<(String, String)> = Vec::new();
    let mut cur_root = String::new();
    let mut last_push = Instant::now();
    let mut pend_files = 0u64;
    let mut pend_bytes = 0u64;
    let mut aborted = false;
    let mut done_ok = false;
    let dest = dest_ui;

    let result: io::Result<()> = (|| {
        loop {
            if state.cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            let line = conn.read_msg()?;
            let f = fields(&line);
            if f.is_empty() {
                continue;
            }
            match f[0].as_str() {
                "PLAN" => {
                    let nf: u64 = f.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let nb: u64 = f.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                    job_plan(&state, &job_id, widx, nf, nb);
                    let (ft, bt) = {
                        let jl = state.job.lock().unwrap();
                        match jl.as_ref() {
                            Some(j) if j.id == job_id => (j.files_total, j.bytes_total),
                            _ => (nf, nb),
                        }
                    };
                    let mut u = state.lock();
                    u.prog.files_total = ft;
                    u.prog.bytes_total = bt;
                }
                "ROOT" => cur_root = f.get(1).cloned().unwrap_or_default(),
                "DIR" => {
                    let rel = f.get(1).cloned().unwrap_or_default();
                    let _ = fs::create_dir_all(dest.join(&cur_root).join(rel));
                }
                "ABORT" => {
                    aborted = true;
                    break;
                }
                "BATCH" => {
                    let n: usize = f.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let mut items: Vec<(String, u64, u64)> = Vec::with_capacity(n);
                    for _ in 0..n {
                        let l = conn.read_msg()?;
                        let ff = fields(&l);
                        if ff.len() < 4 {
                            continue;
                        }
                        items.push((ff[1].clone(), ff[2].parse().unwrap_or(0), ff[3].parse().unwrap_or(0)));
                    }
                    let _ = conn.read_msg()?; // BEND
                    let base = dest.join(&cur_root);

                    let mut decs: Vec<(bool, u64, PathBuf, PathBuf)> = Vec::with_capacity(items.len());
                    for (rel, size, mtime) in &items {
                        let final_path = base.join(rel);
                        let mut part_os = final_path.as_os_str().to_os_string();
                        part_os.push(".lxferpart");
                        let part_path = PathBuf::from(part_os);
                        let mut skip = false;
                        if let Ok(md) = fs::metadata(&final_path) {
                            if md.is_file() && md.len() == *size {
                                let existing = mtime_of(&md);
                                let diff = if *mtime > existing { *mtime - existing } else { existing - *mtime };
                                if diff <= 2 {
                                    skip = true;
                                }
                            }
                        }
                        let mut off = 0u64;
                        if !skip {
                            if let Ok(md) = fs::metadata(&part_path) {
                                let plen = md.len();
                                if plen > 0 && plen < *size {
                                    off = plen;
                                }
                            }
                            if let Some(par) = final_path.parent() {
                                let _ = fs::create_dir_all(par);
                            }
                        }
                        decs.push((skip, off, final_path, part_path));
                    }

                    conn.put_line(&format!("DEC\t{}", items.len()))?;
                    for (skip, off, _, _) in &decs {
                        if *skip {
                            conn.put_line("S")?;
                        } else {
                            conn.put_line(&format!("G\t{}", off))?;
                        }
                    }
                    conn.put_line("DEND")?;
                    conn.flush()?;

                    let mut batch_fail: Vec<(String, String)> = Vec::new();
                    let mut frame: Vec<u8> = Vec::new();
                    for idx in 0..items.len() {
                        if state.cancel.load(Ordering::Relaxed) {
                            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                        }
                        let (rel, size, mtime) = &items[idx];
                        let (skip, off, final_path, part_path) = &decs[idx];
                        if *skip {
                            skipped += 1;
                            pend_files += 1;
                            continue;
                        }
                        let expected = *size - *off;
                        let mut fo = OpenOptions::new().create(true).write(true).truncate(false).open(part_path)?;
                        fo.seek(SeekFrom::Start(*off))?;
                        fo.set_len(*off)?;
                        let mut crc = 0xFFFF_FFFFu32;
                        let mut got = 0u64;
                        loop {
                            if state.cancel.load(Ordering::Relaxed) {
                                let _ = fo.flush();
                                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                            }
                            if !conn.read_frame(&mut frame)? {
                                break;
                            }
                            fo.write_all(&frame)?;
                            crc = crc_update(&t, crc, &frame);
                            got += frame.len() as u64;
                            pend_bytes += frame.len() as u64;
                            if last_push.elapsed() >= Duration::from_millis(160) {
                                ui_from_job(&state, &job_id, pend_files, pend_bytes, rel);
                                pend_files = 0;
                                pend_bytes = 0;
                                last_push = Instant::now();
                            }
                        }
                        fo.flush()?;
                        let line2 = conn.read_msg()?;
                        let lf = fields(&line2);
                        let sender_crc: u64 = if lf.len() >= 2 { lf[1].parse().unwrap_or(0) } else { 1 };
                        let ok = got == expected && sender_crc == (!crc) as u64;
                        if ok {
                            set_mtime(&fo, *mtime);
                            drop(fo);
                            match fs::rename(part_path, final_path) {
                                Ok(_) => {
                                    copied += 1;
                                    bytes += expected;
                                }
                                Err(e) => {
                                    let _ = fs::remove_file(part_path);
                                    failed += 1;
                                    batch_fail.push((
                                        final_path.to_string_lossy().to_string(),
                                        format!("改名失败: {}", e),
                                    ));
                                }
                            }
                        } else {
                            drop(fo);
                            let _ = fs::remove_file(part_path);
                            failed += 1;
                            let reason = if got != expected {
                                format!("数据不完整: 期望 {} 字节，收到 {}", expected, got)
                            } else {
                                "CRC 校验不通过".into()
                            };
                            batch_fail.push((final_path.to_string_lossy().to_string(), reason));
                        }
                        pend_files += 1;
                        if last_push.elapsed() >= Duration::from_millis(160) {
                            ui_from_job(&state, &job_id, pend_files, pend_bytes, rel);
                            pend_files = 0;
                            pend_bytes = 0;
                            last_push = Instant::now();
                        }
                    }

                    conn.put_line(&format!("R\t{}", batch_fail.len()))?;
                    for (fp, reason) in &batch_fail {
                        conn.put_line(&format!("X\t{}\t{}", esc(fp), esc(reason)))?;
                    }
                    conn.flush()?;
                    failed_list.extend(batch_fail);
                }
                "DONE" => {
                    // 采用发送端的权威统计（跨重连仍准确），避免重连后重复计数
                    if let Some(v) = f.get(3).and_then(|s| s.parse::<u64>().ok()) {
                        copied = v;
                    }
                    if let Some(v) = f.get(4).and_then(|s| s.parse::<u64>().ok()) {
                        skipped = v;
                    }
                    if let Some(v) = f.get(5).and_then(|s| s.parse::<u64>().ok()) {
                        failed = v;
                    }
                    if let Some(v) = f.get(6).and_then(|s| s.parse::<u64>().ok()) {
                        bytes = v;
                    }
                    done_ok = true;
                    conn.send_line(&format!(
                        "FINAL\t{}\t{}\t{}\t{}\t{}",
                        copied,
                        skipped,
                        failed,
                        bytes,
                        esc(&dest.to_string_lossy())
                    ))?;
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    })();

    if done_ok {
        let already = {
            let jl = state.job.lock().unwrap();
            match jl.as_ref() {
                Some(j) if j.id == job_id => j.done.get(widx as usize).copied().unwrap_or(false),
                _ => true,
            }
        };
        if !already {
            job_add_result(&state, &job_id, copied, skipped, failed, bytes, failed_list);
        }
        job_worker_done(&state, &job_id, widx, true, None);
    } else if aborted {
    } else if aborted {
        job_worker_done(&state, &job_id, widx, true, Some("发送方重试次数用尽".into()));
    } else {
        let emsg = result.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
        job_worker_done(&state, &job_id, widx, false, Some(emsg));
    }
}
fn write_report(dest: &Path, peer: &SocketAddr, st: &Res) -> Option<PathBuf> {
    let name = format!("lxfer-report-{}.txt", now_secs());
    let path = dest.join(&name);
    let mut s = String::new();
    s.push_str("lxfer 传输报告\n====================\n");
    s.push_str(&format!("时间: {}\n", beijing_now()));
    s.push_str(&format!("发送方: {}\n", peer.ip()));
    s.push_str(&format!("保存到: {}\n", dest.to_string_lossy()));
    s.push_str(&format!(
        "结果: 复制 {} 个，跳过 {} 个（已存在且一致），失败 {} 个\n",
        st.copied, st.skipped, st.failed
    ));
    s.push_str(&format!(
        "本次传输: {}，耗时 {:.0} 秒，平均 {:.1} MB/s\n",
        human_size(st.bytes),
        st.elapsed,
        st.avg_speed / 1024.0 / 1024.0
    ));
    if st.failed_list.is_empty() {
        s.push_str("校验: 全部文件 CRC32 通过\n");
    } else {
        s.push_str(&format!("失败清单（{} 个）:\n", st.failed_list.len()));
        for (p, r) in st.failed_list.iter().take(2000) {
            s.push_str(&format!("  - {}  [{}]\n", p, r));
        }
    }
    let mut data = Vec::with_capacity(s.len() + 3);
    data.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    data.extend_from_slice(s.as_bytes());
    fs::write(&path, &data).ok()?;
    Some(path)
}

// ---------- 传输引擎：发送 ----------
struct SrcTree {
    root: String,
    path: PathBuf,
    dirs: Vec<String>,
    files: Vec<Entry>,
}

struct Task {
    root: String,
    base: PathBuf,
    rel: String,
    size: u64,
    mtime: u64,
}

struct Agg {
    files: std::sync::atomic::AtomicU64,
    bytes: std::sync::atomic::AtomicU64,
    cur: Mutex<String>,
}

fn send_worker_once(
    state: &Arc<AppState>,
    job_id: &str,
    widx: u32,
    wcount: u32,
    host: &str,
    port: u16,
    code: &str,
    tasks: &Arc<Vec<Task>>,
    dirs: &Arc<Vec<(String, Vec<String>)>>,
    mine: &[usize],
    states: &mut [u8],
    cursor: &mut usize,
    agg: &Arc<Agg>,
    total_bytes: u64,
    finished: &Arc<Vec<AtomicBool>>,
    finfo: &Arc<Mutex<Vec<Option<(u64, u64, u64, u64)>>>>,
) -> io::Result<()> {
    let t = crctab();
    let stream = TcpStream::connect(format!("{}:{}", host, port))?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
    let mut conn = Conn::new(&stream)?;

    // 握手（含 ECDH 公钥 + 本次任务总字节，用于接收端空间预检）
    let mut crypto = Crypto::new();
    let pub_hex = match crypto.as_ref() {
        Some(c) => c.pub_hex(),
        None => String::new(),
    };
    let done_mask: u32 = {
        let mut m = 0u32;
        for (i, f) in finished.iter().enumerate().take(32) {
            if f.load(Ordering::Relaxed) {
                m |= 1 << i;
            }
        }
        m
    };
    let done_info: String = {
        let fi = match finfo.lock() {
            Ok(g) => g.clone(),
            Err(_) => Vec::new(),
        };
        let mut parts: Vec<String> = Vec::new();
        for i in 0..fi.len().min(32) {
            if finished.get(i).map(|f| f.load(Ordering::Relaxed)).unwrap_or(false) {
                if let Some((c, s, f, b)) = fi[i] {
                    parts.push(format!("{},{},{},{},{}", i, c, s, f, b));
                }
            }
        }
        parts.join(";")
    };
    conn.send_line(&format!(
        "HELLO2\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
        esc(code),
        esc(&hostname()),
        esc(job_id),
        widx,
        wcount,
        pub_hex,
        total_bytes,
        done_mask,
        done_info
    ))?;
    let resp = conn.read_msg()?;
    if !resp.starts_with("WELCOME") {
        let rf = fields(&resp);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            rf.get(1).cloned().unwrap_or_else(|| "被接收端拒绝".into()),
        ));
    }
    let wf = fields(&resp);
    let enc = wf.get(1).map(|s| s == "1").unwrap_or(false);
    if enc {
        let peer_pub = wf.get(2).cloned().unwrap_or_default();
        let ok = match crypto.as_mut() {
            Some(c) => c.derive(&peer_pub, &code),
            None => false,
        };
        if !ok {
            return Err(io::Error::new(io::ErrorKind::Other, "加密协商失败"));
        }
        if let Some(c) = crypto.take() {
            conn.set_crypto(c);
        }
    } else {
        crypto = None;
        state.message("接收端未启用加密，本次传输为明文");
    }
    {
        let mut u = state.lock();
        u.secure = enc;
    }

    let my_total: u64 = mine.iter().map(|&i| tasks[i].size).sum();
    conn.send_line(&format!("PLAN\t{}\t{}", mine.len() as u64, my_total))?;

    // 目录只需报一次（空目录也要建）
    if widx == 0 {
        for (root, dl) in dirs.iter() {
            conn.put_line(&format!("ROOT\t{}", esc(root)))?;
            for d in dl {
                conn.put_line(&format!("DIR\t{}", esc(d)))?;
            }
        }
        conn.flush()?;
    }

    let mut cur_root = String::new();
    let mut frame: Vec<u8> = vec![0u8; CHUNK];
    while *cursor < mine.len() {
        if state.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        let start = *cursor;
        let root = tasks[mine[start]].root.clone();
        let mut batch: Vec<usize> = Vec::new();
        let mut batch_bytes = 0u64;
        let mut j = start;
        while j < mine.len()
            && tasks[mine[j]].root == root
            && batch.len() < BATCH_FILES
            && (batch.is_empty() || batch_bytes + tasks[mine[j]].size <= BATCH_BYTES)
        {
            batch_bytes += tasks[mine[j]].size;
            batch.push(j);
            j += 1;
        }
        if root != cur_root {
            conn.send_line(&format!("ROOT\t{}", esc(&root)))?;
            cur_root = root.clone();
        }
        conn.put_line(&format!("BATCH\t{}", batch.len()))?;
        for &j2 in &batch {
            let tb = &tasks[mine[j2]];
            conn.put_line(&format!("F\t{}\t{}\t{}", esc(&tb.rel), tb.size, tb.mtime))?;
        }
        conn.put_line("BEND")?;
        conn.flush()?;

        let dec_head = conn.read_msg()?;
        let dh = fields(&dec_head);
        if dh.first().map(|s| s.as_str()) != Some("DEC") {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "接收端响应异常"));
        }
        let mut decs: Vec<Option<u64>> = Vec::with_capacity(batch.len());
        for _ in 0..batch.len() {
            let l = conn.read_msg()?;
            let ff = fields(&l);
            if ff.is_empty() || ff[0] == "S" {
                decs.push(None);
            } else {
                decs.push(Some(ff.get(1).and_then(|s| s.parse().ok()).unwrap_or(0)));
            }
        }
        let _ = conn.read_msg()?; // DEND

        for (bi, &j2) in batch.iter().enumerate() {
            if state.cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            let task = &tasks[mine[j2]];
            let slot = j2;
            let off = match decs[bi] {
                None => {
                    states[slot] = 1;
                    agg.files.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                Some(o) => o,
            };
            {
                let mut c = agg.cur.lock().unwrap();
                *c = format!("{}\\{}", task.root, task.rel);
            }
            let path = task.base.join(&task.rel);
            let mut fo = match File::open(&path) {
                Ok(f) => f,
                Err(_) => {
                    conn.write_frame(&[])?;
                    conn.put_line("C\t0")?;
                    continue;
                }
            };
            if off > 0 {
                let _ = fo.seek(SeekFrom::Start(off));
            }
            let expected = task.size.saturating_sub(off);
            let mut crc = 0xFFFF_FFFFu32;
            let mut sent = 0u64;
            while sent < expected {
                if state.cancel.load(Ordering::Relaxed) {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
                }
                let want = std::cmp::min(CHUNK as u64, expected - sent) as usize;
                match fo.read(&mut frame[..want]) {
                    Ok(0) => break,
                    Ok(n) => {
                        conn.write_frame(&frame[..n])?;
                        crc = crc_update(&t, crc, &frame[..n]);
                        sent += n as u64;
                        agg.bytes.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
            conn.write_frame(&[])?;
            conn.put_line(&format!("C\t{}", !crc))?;
            states[slot] = 2;
            agg.files.fetch_add(1, Ordering::Relaxed);
        }
        conn.flush()?;

        let rline = conn.read_msg()?;
        let rf = fields(&rline);
        let nf: usize = rf.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
        let mut fails: Vec<String> = Vec::with_capacity(nf);
        for _ in 0..nf {
            let l = conn.read_msg()?;
            let ff = fields(&l);
            fails.push(ff.get(1).cloned().unwrap_or_default());
        }
        for &j2 in &batch {
            let task = &tasks[mine[j2]];
            if states[j2] == 2 && fails.iter().any(|x| x.ends_with(&task.rel)) {
                states[j2] = 0;
            }
        }
        *cursor = j;
    }

    let mut r_copied = 0u64;
    let mut r_skipped = 0u64;
    let mut r_bytes = 0u64;
    for (k, &mi) in mine.iter().enumerate() {
        match states.get(k).copied().unwrap_or(0) {
            1 => r_skipped += 1,
            2 => {
                r_copied += 1;
                r_bytes += tasks[mi].size;
            }
            _ => {}
        }
    }
    let r_failed = (mine.len() as u64).saturating_sub(r_copied + r_skipped);
    if let Ok(mut v) = finfo.lock() {
        if let Some(slot) = v.get_mut(widx as usize) {
            *slot = Some((r_copied, r_skipped, r_failed, r_bytes));
        }
    }
    conn.send_line(&format!(
        "DONE\t{}\t{}\t{}\t{}\t{}\t{}",
        mine.len() as u64,
        my_total,
        r_copied,
        r_skipped,
        r_failed,
        r_bytes
    ))?;
    let fin = conn.read_msg()?;
    let _ = fin;
    Ok(())
}

fn send_abort(host: &str, port: u16, code: &str, job_id: &str, widx: u32, wcount: u32, total_bytes: u64) {
    if let Ok(stream) = TcpStream::connect(format!("{}:{}", host, port)) {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        if let Ok(mut conn) = Conn::new(&stream) {
            let _ = conn.send_line(&format!(
                "HELLO2\t{}\t{}\t{}\t{}\t{}\t-\t{}",
                esc(code),
                esc(&hostname()),
                esc(job_id),
                widx,
                wcount,
                total_bytes
            ));
            let _ = conn.read_msg();
            let _ = conn.send_line("ABORT");
            let _ = conn.flush();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn send_worker(
    state: &Arc<AppState>,
    job_id: &str,
    widx: u32,
    wcount: u32,
    host: &str,
    port: u16,
    code: &str,
    tasks: Arc<Vec<Task>>,
    dirs: Arc<Vec<(String, Vec<String>)>>,
    mine: Vec<usize>,
    agg: Arc<Agg>,
    total_bytes: u64,
    finished: Arc<Vec<AtomicBool>>,
    finfo: Arc<Mutex<Vec<Option<(u64, u64, u64, u64)>>>>,
) -> (Vec<u8>, Vec<String>) {
    let mut states = vec![0u8; mine.len()];
    let mut cursor = 0usize;
    let mut errors: Vec<String> = Vec::new();
    let mut attempt = 0u32;
    loop {
        if state.cancel.load(Ordering::Relaxed) {
            break;
        }
        match send_worker_once(
            state, job_id, widx, wcount, host, port, code, &tasks, &dirs, &mine, &mut states, &mut cursor, &agg, total_bytes, &finished, &finfo,
        ) {
            Ok(()) => {
                if let Some(f) = finished.get(widx as usize) {
                    f.store(true, Ordering::SeqCst);
                }
                break;
            }
            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted {
                }
                if e.to_string().contains("配对码") || e.to_string().contains("空间不足") || e.to_string().contains("协议不匹配") {
                    errors.push(format!("第 {} 路：{}", widx + 1, e));
                    break;
                }
                attempt += 1;
                if attempt > 4 {
                    errors.push(format!("第 {} 路连接重试 4 次仍失败：{}", widx + 1, e));
                    send_abort(host, port, code, job_id, widx, wcount, total_bytes);
                    break;
                }
                state.message(&format!("连接中断，{} 秒后自动重连（第 {} 次）…", 2 * attempt, attempt));
                thread::sleep(Duration::from_secs(2 * attempt as u64));
            }
        }
    }
    (states, errors)
}

fn send_run(state: Arc<AppState>, host: String, port: u16, code: String, srcs: Vec<String>) {
    let started = Instant::now();
    {
        let mut u = state.lock();
        u.phase = "transferring".into();
        u.result = None;
        u.error.clear();
        u.secure = false;
        u.prog = Prog::default();
        u.prog.current = "正在统计要传输的文件…".into();
        u.message.clear();
    }

    // 收集源：目录递归展开；单个文件直接作为一个任务
    struct Group {
        root: String,
        base: PathBuf,
        dirs: Vec<String>,
        files: Vec<Entry>,
    }
    let mut groups: Vec<Group> = Vec::new();
    for s in &srcs {
        let p = PathBuf::from(s);
        if p.is_dir() {
            let mut dirs = Vec::new();
            let mut files = Vec::new();
            walk_dir(&p, &p, &mut dirs, &mut files);
            groups.push(Group { root: root_name(&p), base: p.clone(), dirs, files });
        } else if p.is_file() {
            if let Ok(md) = fs::metadata(&p) {
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                if !name.is_empty() {
                    let base = p.parent().map(|x| x.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
                    groups.push(Group {
                        root: file_root(&p),
                        base,
                        dirs: Vec::new(),
                        files: vec![Entry { rel: name, size: md.len(), mtime: mtime_of(&md) }],
                    });
                }
            }
        }
    }
    // 不同来源根名相同时自动加后缀，避免同名目录互相覆盖
    let mut used_roots: Vec<String> = Vec::new();
    for g in groups.iter_mut() {
        let base_name = g.root.clone();
        let mut cand = base_name.clone();
        let mut n = 2;
        while used_roots.iter().any(|r| r.eq_ignore_ascii_case(&cand)) {
            cand = format!("{} ({})", base_name, n);
            n += 1;
        }
        used_roots.push(cand.clone());
        g.root = cand;
    }
    let mut tasks: Vec<Task> = Vec::new();
    let mut dir_groups: Vec<(String, Vec<String>)> = Vec::new();
    for g in groups {
        dir_groups.push((g.root.clone(), g.dirs));
        for e in g.files {
            tasks.push(Task {
                root: g.root.clone(),
                base: g.base.clone(),
                rel: e.rel,
                size: e.size,
                mtime: e.mtime,
            });
        }
    }
    let total_files = tasks.len() as u64;
    let total_bytes: u64 = tasks.iter().map(|t| t.size).sum();

    if tasks.is_empty() {
        let mut u = state.lock();
        u.phase = "error".into();
        u.error = "没有可发送的文件".into();
        drop(u);
        state.running.store(false, Ordering::SeqCst);
        return;
    }

    let wcount: u32 = if total_files >= 2000 {
        8
    } else if total_files >= 300 {
        6
    } else {
        4
    };
    let finished: Arc<Vec<AtomicBool>> = Arc::new((0..wcount).map(|_| AtomicBool::new(false)).collect());
    let finfo: Arc<Mutex<Vec<Option<(u64, u64, u64, u64)>>>> = Arc::new(Mutex::new(vec![None; wcount as usize]));
    {
        let mut u = state.lock();
        u.prog.files_total = total_files;
        u.prog.bytes_total = total_bytes;
        u.prog.workers = wcount;
        u.prog.current = format!("正在建立 {} 条并行连接…", wcount);
    }

    // LPT 均衡分配
    let mut order: Vec<usize> = (0..tasks.len()).collect();
    order.sort_by(|&a, &b| tasks[b].size.cmp(&tasks[a].size));
    let mut buckets: Vec<Vec<usize>> = vec![Vec::new(); wcount as usize];
    let mut loads: Vec<u64> = vec![0; wcount as usize];
    for idx in order {
        let w = loads
            .iter()
            .enumerate()
            .min_by_key(|(_, v)| **v)
            .map(|(i, _)| i)
            .unwrap_or(0);
        loads[w] += tasks[idx].size;
        buckets[w].push(idx);
    }
    for b in buckets.iter_mut() {
        b.sort_by(|&a, &c| {
            tasks[a]
                .root
                .cmp(&tasks[c].root)
                .then_with(|| tasks[a].rel.cmp(&tasks[c].rel))
        });
    }
    let layout: Vec<Vec<usize>> = buckets.clone();

    let job_id = format!("{}-{}", now_millis(), std::process::id());
    let tasks = Arc::new(tasks);
    let dirs = Arc::new(dir_groups);
    let agg = Arc::new(Agg {
        files: std::sync::atomic::AtomicU64::new(0),
        bytes: std::sync::atomic::AtomicU64::new(0),
        cur: Mutex::new(String::new()),
    });

    let stop = Arc::new(AtomicBool::new(false));
    let mon = {
        let st = state.clone();
        let ag = agg.clone();
        let sp = stop.clone();
        thread::spawn(move || {
            let mut last = Instant::now();
            let mut last_bytes = 0u64;
            while !sp.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(300));
                let files = ag.files.load(Ordering::Relaxed);
                let bytes = ag.bytes.load(Ordering::Relaxed);
                let dt = last.elapsed().as_secs_f64().max(0.001);
                let speed = bytes.saturating_sub(last_bytes) as f64 / dt;
                last = Instant::now();
                last_bytes = bytes;
                let cur = ag.cur.lock().unwrap().clone();
                let mut u = st.lock();
                if u.phase == "transferring" {
                    u.prog.files_done = files;
                    u.prog.bytes_done = bytes;
                    u.prog.files_total = total_files;
                    u.prog.bytes_total = total_bytes;
                    u.prog.speed = speed;
                    u.prog.eta = if speed > 1.0 && total_bytes > bytes {
                        ((total_bytes - bytes) as f64 / speed) as u64
                    } else {
                        0
                    };
                    u.prog.current = cur;
                    u.prog.workers = wcount;
                }
            }
        })
    };

    let mut handles = Vec::new();
    for (widx, mine) in buckets.into_iter().enumerate() {
        let st = state.clone();
        let tk = tasks.clone();
        let dr = dirs.clone();
        let ag = agg.clone();
        let h = host.clone();
        let cd = code.clone();
        let jid = job_id.clone();
        let fin = finished.clone();
        let fi = finfo.clone();
        handles.push(thread::spawn(move || {
            send_worker(
                &st,
                &jid,
                widx as u32,
                wcount,
                &h,
                port,
                &cd,
                tk,
                dr,
                mine,
                ag,
                total_bytes,
                fin,
                fi,
            )
        }));
    }

    let mut total = Res::default();
    let mut errors: Vec<String> = Vec::new();
    for (wi, h) in handles.into_iter().enumerate() {
        match h.join() {
            Ok((states, errs)) => {
                errors.extend(errs);
                for (k, &mi) in layout[wi].iter().enumerate() {
                    match states.get(k).copied().unwrap_or(0) {
                        1 => total.skipped += 1,
                        2 => {
                            total.copied += 1;
                            total.bytes += tasks[mi].size;
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => errors.push("传输线程异常".into()),
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = mon.join();

    total.failed = total_files.saturating_sub(total.copied + total.skipped);
    total.elapsed = started.elapsed().as_secs_f64();
    total.avg_speed = if total.elapsed > 0.0 {
        total.bytes as f64 / total.elapsed
    } else {
        0.0
    };
    let cancelled = state.cancel.load(Ordering::Relaxed);
    let mut u = state.lock();
    if cancelled {
        u.phase = "idle".into();
        u.message = "已取消，重新开始会从断点继续".into();
    } else if !errors.is_empty() {
        u.phase = "error".into();
        u.error = errors.join("；");
        u.message.clear();
        u.result = Some(total);
    } else {
        u.prog.bytes_done = total.bytes;
        u.prog.files_done = total_files;
        u.result = Some(total);
        u.phase = "done".into();
        u.message.clear();
    }
    drop(u);
    state.running.store(false, Ordering::SeqCst);
}
fn recv_listener(state: Arc<AppState>, listener: TcpListener) {
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        let peer = match stream.peer_addr() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let (mode, code, dest) = {
            let u = state.lock();
            (u.mode.clone(), u.code.clone(), u.dest.clone())
        };
        if mode != "recv" || code.is_empty() || dest.is_empty() {
            let _ = stream.shutdown(Shutdown::Both);
            continue;
        }
        let st = state.clone();
        thread::spawn(move || recv_session(st, stream, peer, code, PathBuf::from(dest)));
    }
}
// ---------- 设备发现 ----------
fn subnet_broadcast() -> Option<String> {
    let ip = local_ip();
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() == 4 {
        Some(format!("{}.{}.{}.255:{}", parts[0], parts[1], parts[2], DISCOVER_PORT))
    } else {
        None
    }
}
fn probe_devices() -> Vec<Dev> {
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    let _ = sock.set_broadcast(true);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(350)));
    let mut targets = vec![format!("255.255.255.255:{}", DISCOVER_PORT)];
    if let Some(b) = subnet_broadcast() {
        targets.push(b);
    }
    for _ in 0..2 {
        for t in &targets {
            let _ = sock.send_to(b"LXFER_DISCOVER", t);
        }
        thread::sleep(Duration::from_millis(120));
    }
    let my_ip = local_ip();
    let mut out: Vec<Dev> = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = Instant::now() + Duration::from_millis(1600);
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                if let Some(rest) = msg.strip_prefix("LXFER_HERE\t") {
                    let f: Vec<&str> = rest.split('\t').collect();
                    let ip = src.ip().to_string();
                    if ip == my_ip {
                        continue;
                    }
                    let name = f.first().map(|s| s.to_string()).unwrap_or_else(|| "对方电脑".into());
                    let port = f.get(1).and_then(|s| s.parse().ok()).unwrap_or(XFER_PORT_DEFAULT);
                    if !out.iter().any(|d| d.ip == ip) {
                        out.push(Dev { name, ip, port });
                    }
                }
            }
            Err(_) => break,
        }
    }
    out
}
fn discovery_responder(state: Arc<AppState>) {
    let sock = match UdpSocket::bind(("0.0.0.0", DISCOVER_PORT)) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_secs(1)));
    let mut buf = [0u8; 256];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                let msg = String::from_utf8_lossy(&buf[..n]).to_string();
                if msg.starts_with("LXFER_DISCOVER") {
                    let (mode, port) = {
                        let u = state.lock();
                        (u.mode.clone(), state.xfer_port)
                    };
                    if mode == "recv" {
                        let reply = format!("LXFER_HERE\t{}\t{}", hostname(), port);
                        let _ = sock.send_to(reply.as_bytes(), src);
                    }
                }
            }
            Err(_) => {}
        }
    }
}
fn discovery_loop(state: Arc<AppState>) {
    loop {
        let mode = state.lock().mode.clone();
        if mode == "send" {
            let devs = probe_devices();
            state.lock().devices = devs;
            thread::sleep(Duration::from_secs(2));
        } else {
            thread::sleep(Duration::from_secs(1));
        }
    }
}

// ---------- 原生对话框 ----------
fn pick_folder_native(initial: &str, title: &str) -> Option<String> {
    let script = r#"Add-Type -AssemblyName System.Windows.Forms
$o = New-Object System.Windows.Forms.Form
$o.TopMost = $true
$o.ShowInTaskbar = $false
$o.WindowState = 'Minimized'
$d = New-Object System.Windows.Forms.FolderBrowserDialog
$d.ShowNewFolderButton = $true
if ($env:LXFER_TITLE) { $d.Description = $env:LXFER_TITLE }
if ($env:LXFER_INIT -and (Test-Path -LiteralPath $env:LXFER_INIT)) { $d.SelectedPath = $env:LXFER_INIT }
$r = $d.ShowDialog($o)
$o.Dispose()
if ($r -eq [System.Windows.Forms.DialogResult]::OK) { [Console]::Out.Write($d.SelectedPath) }"#;
    let out = Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", script])
        .env("LXFER_INIT", initial)
        .env("LXFER_TITLE", title)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}
fn pick_files_native(title: &str) -> Vec<String> {
    let script = r#"Add-Type -AssemblyName System.Windows.Forms
$o = New-Object System.Windows.Forms.Form
$o.TopMost = $true
$o.ShowInTaskbar = $false
$o.WindowState = 'Minimized'
$d = New-Object System.Windows.Forms.OpenFileDialog
$d.Multiselect = $true
$d.CheckFileExists = $true
$d.Title = $env:LXFER_TITLE
$r = $d.ShowDialog($o)
$o.Dispose()
if ($r -eq [System.Windows.Forms.DialogResult]::OK) { foreach ($f in $d.FileNames) { [Console]::Out.WriteLine($f) } }"#;
    let out = match Command::new("powershell")
        .args(["-NoProfile", "-STA", "-Command", script])
        .env("LXFER_TITLE", title)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
    {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
fn open_folder(path: &str) {
    if path.is_empty() {
        return;
    }
    let _ = Command::new("explorer.exe").arg(path).creation_flags(CREATE_NO_WINDOW).spawn();
}

// ---------- HTTP ----------
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
fn write_response(stream: &mut TcpStream, ctype: &str, body: &[u8]) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        ctype,
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}
fn handle_http(mut stream: TcpStream, state: Arc<AppState>) {
    state.last_req_ms.store(now_millis(), Ordering::Relaxed);
    stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        if find_sub(&buf, b"\r\n\r\n").is_some() {
            break;
        }
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() > 1 << 20 {
                    break;
                }
            }
            Err(_) => return,
        }
    }
    let head = String::from_utf8_lossy(&buf).to_string();
    let mut lines = head.lines();
    let req_line = lines.next().unwrap_or("").to_string();
    let mut rp = req_line.split_whitespace();
    let method = rp.next().unwrap_or("GET").to_string();
    let path = rp.next().unwrap_or("/").split('?').next().unwrap_or("/").to_string();
    let mut clen = 0usize;
    for l in lines {
        let low = l.to_ascii_lowercase();
        if let Some(v) = low.strip_prefix("content-length:") {
            clen = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = Vec::new();
    if let Some(he) = find_sub(&buf, b"\r\n\r\n") {
        let start = he + 4;
        if start < buf.len() {
            body.extend_from_slice(&buf[start..]);
        }
    }
    while body.len() < clen {
        match stream.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&tmp[..n]),
            Err(_) => break,
        }
    }
    let body_s = String::from_utf8_lossy(&body).to_string();

    if method == "GET" && (path == "/" || path == "/index.html") {
        let _ = write_response(&mut stream, "text/html; charset=utf-8", UI_HTML.as_bytes());
        return;
    }
    if method == "GET" && path == "/api/state" {
        let js = {
            let u = state.lock();
            state_json(&u)
        };
        let _ = write_response(&mut stream, "application/json; charset=utf-8", js.as_bytes());
        return;
    }
    let ok = if method == "POST" { handle_action(&state, &path, &body_s) } else { false };
    let resp = if ok { "{\"ok\":true}" } else { "{\"ok\":false}" };
    let _ = write_response(&mut stream, "application/json; charset=utf-8", resp.as_bytes());
}

fn get_num(body: &str, key: &str) -> u64 {
    if let Some(i) = body.find(&format!("\"{}\"", key)) {
        let rest = &body[i + key.len() + 2..];
        if let Some(c) = rest.find(':') {
            let r2 = rest[c + 1..].trim_start();
            let mut val = 0u64;
            let mut any = false;
            for ch in r2.chars() {
                if let Some(d) = ch.to_digit(10) {
                    val = val.saturating_mul(10).saturating_add(d as u64);
                    any = true;
                } else if any {
                    break;
                } else if ch == '"' {
                    continue;
                } else {
                    break;
                }
            }
            return if any { val } else { 0 };
        }
    }
    0
}
fn get_str(body: &str, key: &str) -> String {
    // 极简 JSON 取字符串字段（只服务自家前端）
    if let Some(i) = body.find(&format!("\"{}\"", key)) {
        let rest = &body[i + key.len() + 2..];
        if let Some(c) = rest.find(':') {
            let r2 = rest[c + 1..].trim_start();
            if r2.starts_with('"') {
                let mut out = String::new();
                let mut chars = r2[1..].chars();
                while let Some(ch) = chars.next() {
                    match ch {
                        '"' => break,
                        '\\' => {
                            if let Some(n) = chars.next() {
                                match n {
                                    'n' => out.push('\n'),
                                    'r' => out.push('\r'),
                                    't' => out.push('\t'),
                                    '\\' => out.push('\\'),
                                    '"' => out.push('"'),
                                    '/' => out.push('/'),
                                    'u' => {
                                        let hex: String = chars.by_ref().take(4).collect();
                                        if let Ok(v) = u16::from_str_radix(&hex, 16) {
                                            if let Some(c) = char::from_u32(v as u32) {
                                                out.push(c);
                                            }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        c => out.push(c),
                    }
                }
                return out;
            }
        }
    }
    String::new()
}

fn drive_of(path: &str) -> Option<char> {
    let mut it = path.chars();
    let c = it.next()?;
    if c.is_ascii_alphabetic() && it.next() == Some(':') {
        Some(c.to_ascii_uppercase())
    } else {
        None
    }
}
fn refresh_dest_free(ui: &mut Ui) {
    if let Some(l) = drive_of(&ui.dest) {
        ui.dest_free = ui.drives.iter().find(|d| d.letter.starts_with(l)).map(|d| d.free);
    }
}
fn new_code() -> String {
    let seed = now_secs() as u64 * 7919 + (std::process::id() as u64) * 104_729;
    format!("{:06}", (seed % 900_000) + 100_000)
}
fn code_store_path() -> PathBuf {
    match env::var("LOCALAPPDATA") {
        Ok(v) => PathBuf::from(v).join("lxfer").join("pairing-code.txt"),
        Err(_) => env::temp_dir().join("lxfer-pairing-code.txt"),
    }
}
fn load_or_make_code() -> String {
    let p = code_store_path();
    if let Ok(s) = fs::read_to_string(&p) {
        let t = s.trim().to_string();
        if t.len() == 6 && t.chars().all(|c| c.is_ascii_digit()) {
            return t;
        }
    }
    let c = new_code();
    if let Some(dir) = p.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let _ = fs::write(&p, &c);
    c
}
fn reset_to(ui: &mut Ui, mode: &str) {
    ui.mode = mode.to_string();
    ui.phase = "idle".into();
    ui.peer.clear();
    ui.devices.clear();
    ui.srcs.clear();
    ui.prog = Prog::default();
    ui.result = None;
    ui.secure = false;
    ui.error.clear();
    ui.message.clear();
    if mode == "recv" {
        ui.code = load_or_make_code();
    } else {
        ui.code.clear();
    }
}
fn add_src(state: &Arc<AppState>, path: String) {
    let p = PathBuf::from(&path);
    let is_dir = p.is_dir();
    let is_file = p.is_file();
    if !is_dir && !is_file {
        state.message(&format!("路径不存在：{}", path));
        return;
    }
    let mut merged_msg = String::new();
    {
        let mut u = state.lock();
        if u.srcs.iter().any(|s| norm_key(Path::new(&s.path)) == norm_key(&p)) {
            drop(u);
            state.message("这个已经在列表里了");
            return;
        }
        if u.srcs.iter().any(|s| is_same_or_inside(&p, Path::new(&s.path))) {
            drop(u);
            state.message("这个位置已经包含在已选内容里了");
            return;
        }
        let before = u.srcs.len();
        u.srcs.retain(|s| !is_same_or_inside(Path::new(&s.path), &p));
        if u.srcs.len() != before {
            merged_msg = "已自动去重：新内容包含了列表里原有的项".to_string();
        }
        u.srcs.push(Src { path: path.clone(), size: None, scanning: is_dir, is_file });
        if is_file {
            if let Ok(md) = fs::metadata(&p) {
                if let Some(s) = u.srcs.last_mut() {
                    s.size = Some(md.len());
                    s.scanning = false;
                }
            }
        }
    }
    if !merged_msg.is_empty() {
        state.message(&merged_msg);
    }
    if !is_dir {
        return;
    }
    // 目录：后台统计大小
    let st = state.clone();
    thread::spawn(move || {
        let p = PathBuf::from(&path);
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        walk_dir(&p, &p, &mut dirs, &mut files);
        let total: u64 = files.iter().map(|f| f.size).sum();
        let key = norm_key(&p);
        let mut u = st.lock();
        for s in u.srcs.iter_mut() {
            if norm_key(Path::new(&s.path)) == key {
                s.size = Some(total);
                s.scanning = false;
            }
        }
    });
}
fn handle_action(state: &Arc<AppState>, path: &str, body: &str) -> bool {
    match path {
        "/api/mode" => {
            let mode = get_str(body, "mode");
            state.cancel.store(true, Ordering::SeqCst);
            let mut u = state.lock();
            reset_to(&mut u, &mode);
            u.drives = list_drives();
            refresh_dest_free(&mut u);
            true
        }
        "/api/dest" => {
            let p = get_str(body, "path");
            let mut u = state.lock();
            u.dest = p;
            refresh_dest_free(&mut u);
            true
        }
        "/api/add-src" => {
            let p = get_str(body, "path");
            add_src(state, p);
            true
        }
        "/api/remove-src" => {
            let p = get_str(body, "path");
            state.lock().srcs.retain(|s| norm_key(Path::new(&s.path)) != norm_key(Path::new(&p)));
            true
        }
        "/api/pick-folder" => {
            let purpose = get_str(body, "purpose");
            let st = state.clone();
            thread::spawn(move || {
                let (initial, title) = {
                    let u = st.lock();
                    if purpose == "dest" {
                        (u.dest.clone(), "选择保存位置".to_string())
                    } else {
                        (String::new(), "选择要发送的文件夹".to_string())
                    }
                };
                if let Some(p) = pick_folder_native(&initial, &title) {
                    if purpose == "dest" {
                        let mut u = st.lock();
                        u.dest = p;
                        refresh_dest_free(&mut u);
                    } else {
                        add_src(&st, p);
                    }
                }
            });
            true
        }
        "/api/pick-files" => {
            let st = state.clone();
            thread::spawn(move || {
                for path in pick_files_native("选择要发送的文件（可多选）") {
                    add_src(&st, path);
                }
            });
            true
        }
        "/api/discover" => true,
        "/api/send/start" => {
            let ip = get_str(body, "ip");
            let code = get_str(body, "code");
            let (srcs, mode) = {
                let u = state.lock();
                (u.srcs.iter().map(|s| s.path.clone()).collect::<Vec<_>>(), u.mode.clone())
            };
            if mode != "send" || srcs.is_empty() || code.len() != 6 || ip.is_empty() {
                return false;
            }
            if state.running.swap(true, Ordering::SeqCst) {
                state.message("已有任务在进行");
                return false;
            }
            state.cancel.store(false, Ordering::SeqCst);
            let port_req: u16 = get_num(body, "port") as u16;
            let port = if port_req > 0 {
                port_req
            } else {
                let u = state.lock();
                u.devices.iter().find(|d| d.ip == ip).map(|d| d.port).unwrap_or(XFER_PORT_DEFAULT)
            };
            let st = state.clone();
            thread::spawn(move || send_run(st, ip, port, code, srcs));
            true
        }
        "/api/cancel" => {
            state.cancel.store(true, Ordering::SeqCst);
            true
        }
        "/api/open-folder" => {
            let p = get_str(body, "path");
            open_folder(&p);
            true
        }
        _ => false,
    }
}

// ---------- 演示态（截图 / 预览用） ----------
fn apply_demo(state: &Arc<AppState>, name: &str) {
    let mut u = state.lock();
    u.mode = "send".into();
    u.code = "482913".into();
    u.ip = local_ip();
    u.port = XFER_PORT_DEFAULT;
    u.secure = name == "transfer" || name == "done";
    match name {
        "recv" => {
            u.mode = "recv".into();
            u.phase = "idle".into();
        }
        "send" => {
            u.phase = "idle".into();
            u.devices = vec![Dev { name: "DESKTOP-QIU".into(), ip: "192.168.10.30".into(), port: XFER_PORT_DEFAULT }];
            u.srcs = vec![
                Src { path: "D:\\".into(), size: Some(42_000_000_000), scanning: false, is_file: false },
                Src { path: "E:\\".into(), size: Some(88_000_000_000), scanning: false, is_file: false },
            ];
        }
        "transfer" => {
            u.phase = "transferring".into();
            u.peer = "DESKTOP-QIU".into();
            u.prog = Prog {
                files_done: 12_480,
                files_total: 38_215,
                bytes_done: 68_157_000_000,
                bytes_total: 208_000_000_000,
                current: "D:\\照片\\2023\\旅行\\IMG_2048.CR2".into(),
                speed: 78_600_000.0,
                eta: 1780,
                workers: 6,
            };
        }
        "done" => {
            u.mode = "recv".into();
            u.phase = "done".into();
            u.peer = "DESKTOP-QIU".into();
            u.result = Some(Res {
                copied: 38_215,
                skipped: 0,
                failed: 0,
                bytes: 208_000_000_000,
                elapsed: 2712.0,
                avg_speed: 78_600_000.0,
                report: "F:\\OldPC\\lxfer-report-1700000000.txt".into(),
                dest: "F:\\OldPC".into(),
                failed_list: vec![],
            });
        }
        _ => {}
    }
}

// ---------- 启动 ----------
fn open_window(url: &str) {
    let candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ];
    for c in candidates.iter() {
        if Path::new(c).exists() {
            let _ = Command::new(c)
                .args([format!("--app={}", url), "--window-size=1220,880".to_string()])
                .spawn();
            return;
        }
    }
    let _ = Command::new("cmd").args(["/c", "start", "", url]).spawn();
}

fn gui_main(args: &[String]) {
    let mut no_window = false;
    let mut demo = String::new();
    let mut ui_port_req: u16 = 0;
    for a in args.iter().skip(1) {
        if a == "--serve" || a == "--no-window" {
            no_window = true;
        } else if let Some(v) = a.strip_prefix("--demo=") {
            demo = v.to_string();
            no_window = true;
        } else if let Some(v) = a.strip_prefix("--ui-port=") {
            ui_port_req = v.parse().unwrap_or(0);
            no_window = true;
        }
    }

    let ip = local_ip();
    let drives = list_drives();
    let port = {
        let mut chosen = XFER_PORT_DEFAULT;
        for p in XFER_PORT_DEFAULT..XFER_PORT_DEFAULT + 12 {
            if TcpListener::bind(("0.0.0.0", p)).is_ok() {
                chosen = p;
                break;
            }
        }
        chosen
    };
    let default_dest = if drives.iter().any(|d| d.letter == "F") {
        "F:\\OldPC".to_string()
    } else {
        drives
            .iter()
            .max_by_key(|d| d.free)
            .map(|d| format!("{}:\\lxfer-recv", d.letter))
            .unwrap_or_else(|| "C:\\lxfer-recv".into())
    };
    let mut init = Ui::default();
    init.ip = ip.clone();
    init.port = port;
    init.dest = default_dest;
    init.drives = drives;
    refresh_dest_free(&mut init);

    let state = Arc::new(AppState {
        ui: Mutex::new(init),
        running: AtomicBool::new(false),
        cancel: AtomicBool::new(false),
        xfer_port: port,
        last_req_ms: std::sync::atomic::AtomicU64::new(now_millis()),
        job: Mutex::new(None),
        last_job: Mutex::new(String::new()),
    });

    // 接收端监听
    if let Ok(listener) = TcpListener::bind(("0.0.0.0", port)) {
        let s = state.clone();
        thread::spawn(move || recv_listener(s, listener));
    }
    // 设备发现
    {
        let s = state.clone();
        thread::spawn(move || discovery_responder(s));
        if demo.is_empty() {
            let s2 = state.clone();
            thread::spawn(move || discovery_loop(s2));
        }
    }
    // 看门狗：连接异常中断且 150 秒无进展时，结束任务并保留已传部分
    {
        let s = state.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(10));
            let stale = {
                let jl = s.job.lock().unwrap();
                match jl.as_ref() {
                    Some(j) => j.last_change.elapsed() > Duration::from_secs(150),
                    None => false,
                }
            };
            if stale {
                let taken = {
                    let mut jl = s.job.lock().unwrap();
                    jl.take()
                };
                if let Some(mut j) = taken {
                    j.errors.push("连接中断超时（150 秒无数据）".into());
                    finalize_job(&s, j);
                }
            }
        });
    }
    // UI 服务（只监听 127.0.0.1）
    let listener = match TcpListener::bind(("127.0.0.1", ui_port_req)) {
        Ok(l) => l,
        Err(e) => {
            println!("无法启动界面服务: {}", e);
            return;
        }
    };
    let ui_port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
    {
        let s = state.clone();
        thread::spawn(move || {
            for c in listener.incoming() {
                if let Ok(stream) = c {
                    let s2 = s.clone();
                    thread::spawn(move || handle_http(stream, s2));
                }
            }
        });
    }
    if !demo.is_empty() {
        apply_demo(&state, &demo);
    }
    let url = format!("http://127.0.0.1:{}", ui_port);
    println!("lxfer 界面地址: {}", url);
    println!("本机 IP: {}   传输端口: {}", ip, port);
    if !no_window {
        thread::sleep(Duration::from_millis(250));
        open_window(&url);
    }
    // 关掉界面窗口后（页面不再轮询），进程自动退出，避免残留占端口
    loop {
        thread::sleep(Duration::from_secs(10));
        if !no_window {
            let idle = now_millis().saturating_sub(state.last_req_ms.load(Ordering::Relaxed));
            if idle > 180_000 && !state.running.load(Ordering::SeqCst) {
                println!("界面已关闭，进程退出");
                return;
            }
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let gui = args.len() == 1
        || args
            .iter()
            .skip(1)
            .any(|a| a == "--serve" || a == "--no-window" || a == "--gui" || a.starts_with("--demo="));
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
        if gui {
            // 双击启动时把附带的命令行黑窗藏起来，只留界面窗口
            let h = GetConsoleWindow();
            if !h.is_null() {
                ShowWindow(h, 0);
            }
        }
    }
    if !gui {
        println!("lxfer v1.2 —— 局域网换机助手");
        println!();
        println!("双击运行打开图形界面。可选参数：");
        println!("  --serve              只启动服务不打开窗口（调试用）");
        println!("  --ui-port=18001      固定界面端口（调试用）");
        println!("  --demo=transfer      演示态（调试用）");
        println!();
        println!("注意：v1.2 起传输协议改成批量提交，两台电脑必须使用同一个版本。");
        return;
    }
    gui_main(&args);
}
