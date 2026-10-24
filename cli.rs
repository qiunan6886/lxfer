// lxfer —— 局域网搬家 / 备份工具（原型 v0.1）
// 单文件 exe，Windows 双击即用，无需安装任何运行时。
//
// 设计目标：
//   1. 不用开共享、不用建账户、不用改防火墙规则（首次运行放行一次即可）
//   2. 接收端当场选保存目录，发送端选盘/目录，保留原目录结构
//   3. 断点续传（.lxferpart 文件 + 帧协议，断了重跑接着传）
//   4. 逐文件 CRC32 校验 + 完成报告（复制/跳过/失败清单）
//
// 用法：
//   lxfer.exe                      交互菜单
//   lxfer.exe recv [-p 8787] [-d F:\OldPC] [-y] [-once]
//   lxfer.exe send -to 192.168.10.30 [-p 8787] -code 482913 -src "D:\" -src "E:\"
//
// 协议：单条 TCP，控制行用 TAB 分隔（\t 换行符在路径里做转义），
//       数据用 [u32 大端长度][内容] 分帧，0 长度表示文件结束。

use std::cmp::min;
use std::env;
use std::fs::{self, File, FileTimes, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEF_PORT: u16 = 8787;
const BUFSZ: usize = 1024 * 1024;
const CODE_LEN: usize = 6;

// ---------- Windows 控制台 UTF-8（避免中文乱码） ----------
#[link(name = "kernel32")]
extern "system" {
    fn SetConsoleOutputCP(cp: u32) -> i32;
    fn SetConsoleCP(cp: u32) -> i32;
}

// ---------- CRC32 ----------
static CRC_TABLE: OnceLock<[u32; 256]> = OnceLock::new();

fn crctab() -> &'static [u32; 256] {
    CRC_TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for i in 0..256u32 {
            let mut c = i;
            for _ in 0..8 {
                c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
            }
            t[i as usize] = c;
        }
        t
    })
}

fn crc_update(mut crc: u32, data: &[u8]) -> u32 {
    let t = crctab();
    for &b in data {
        crc = t[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc
}
fn crc_finish(c: u32) -> u32 {
    !c
}

// ---------- 时间 / 格式化 ----------
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
fn fmt_bytes(b: u64) -> String {
    let b = b as f64;
    if b >= 1024.0 * 1024.0 * 1024.0 {
        format!("{:.2} GB", b / 1024.0 / 1024.0 / 1024.0)
    } else if b >= 1024.0 * 1024.0 {
        format!("{:.1} MB", b / 1024.0 / 1024.0)
    } else if b >= 1024.0 {
        format!("{:.1} KB", b / 1024.0)
    } else {
        format!("{} B", b as u64)
    }
}
fn fmt_dur(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 {
        format!("{}h{:02}m{:02}s", s / 3600, (s % 3600) / 60, s % 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}s", s)
    }
}

// ---------- 字符串转义（TAB 分隔的协议行） ----------
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

// ---------- 控制行读写 ----------
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
fn send_line(wr: &mut BufWriter<TcpStream>, line: &str) -> io::Result<()> {
    wr.write_all(line.as_bytes())?;
    wr.write_all(b"\n")?;
    wr.flush()
}

// ---------- 交互输入 ----------
fn read_line_lossy() -> String {
    let mut b = Vec::new();
    let _ = io::stdin().lock().read_until(b'\n', &mut b);
    String::from_utf8_lossy(&b).trim_end_matches(['\r', '\n']).to_string()
}
fn ask(prompt: &str) -> String {
    print!("{}", prompt);
    let _ = io::stdout().flush();
    read_line_lossy()
}
fn ask_default(prompt: &str, def: &str) -> String {
    let s = ask(prompt);
    if s.trim().is_empty() { def.to_string() } else { s.trim().to_string() }
}

// ---------- 进度显示 ----------
struct Progress {
    label: &'static str,
    total_files: u64,
    total_bytes: u64,
    files: u64,
    bytes: u64,
    start: Instant,
    last: Instant,
    cur: String,
}
impl Progress {
    fn new(label: &'static str, total_files: u64, total_bytes: u64) -> Self {
        Progress {
            label,
            total_files,
            total_bytes,
            files: 0,
            bytes: 0,
            start: Instant::now(),
            last: Instant::now(),
            cur: String::new(),
        }
    }
    fn set_current(&mut self, name: &str) {
        self.cur = if name.chars().count() > 42 {
            let s: String = name.chars().take(20).collect();
            let e: String = name.chars().rev().take(18).collect::<Vec<_>>().into_iter().rev().collect();
            format!("{}…{}", s, e)
        } else {
            name.to_string()
        };
    }
    fn tick(&mut self, n: u64) {
        self.bytes += n;
        if self.last.elapsed() >= Duration::from_millis(500) {
            self.show();
            self.last = Instant::now();
        }
    }
    fn done_file(&mut self) {
        self.files += 1;
    }
    fn speed(&self) -> f64 {
        let s = self.start.elapsed().as_secs_f64();
        if s <= 0.0 { 0.0 } else { self.bytes as f64 / s }
    }
    fn show(&self) {
        let pct = if self.total_bytes > 0 {
            format!("{:5.1}%", self.bytes as f64 * 100.0 / self.total_bytes as f64)
        } else {
            "     ".to_string()
        };
        let files = if self.total_files > 0 {
            format!("{}/{}", self.files, self.total_files)
        } else {
            format!("{}", self.files)
        };
        let line = format!(
            "  {} 文件 {} {}  {} / {}  {:.1} MB/s  {}",
            self.label,
            files,
            pct,
            fmt_bytes(self.bytes),
            if self.total_bytes > 0 { fmt_bytes(self.total_bytes) } else { "-".to_string() },
            self.speed() / 1024.0 / 1024.0,
            self.cur
        );
        print!("\r{:<118}", line);
        let _ = io::stdout().flush();
    }
    fn finish(&mut self) {
        print!("\r{:<118}\r", "");
        let _ = io::stdout().flush();
    }
}

// ---------- 工具 ----------
fn local_ip() -> String {
    if let Ok(s) = std::net::UdpSocket::bind("0.0.0.0:0") {
        if s.connect("8.8.8.8:80").is_ok() {
            if let Ok(a) = s.local_addr() {
                return a.ip().to_string();
            }
        }
    }
    "127.0.0.1".to_string()
}
fn hostname() -> String {
    env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}
fn gen_code() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u128)
        .unwrap_or(0);
    let seed = now_secs() as u128 * 1_000_000 + (std::process::id() as u128) * 7919 + nanos;
    let n = (seed % 900_000) as u32 + 100_000;
    n.to_string()[..CODE_LEN].to_string()
}
fn root_name(p: &Path) -> String {
    let s = p.to_string_lossy().to_string();
    let t = s.trim_end_matches(['\\', '/']).to_string();
    // "D:" / "D:\" -> "D"
    if t.len() == 2 && t.ends_with(':') {
        return t[..1].to_uppercase();
    }
    match Path::new(&t).file_name() {
        Some(n) => n.to_string_lossy().to_string(),
        None => "root".to_string(),
    }
}

// ---------- 目录遍历 ----------
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
        let p = e.path();
        let fname = e.file_name().to_string_lossy().to_string();
        if should_skip(&fname) {
            continue;
        }
        let md = match e.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.file_type().is_symlink() {
            continue; // 符号链接/目录联接：跳过，避免死循环和跨盘复制
        }
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
        // 符号链接 / 其他类型跳过（避免死循环）
    }
}

// ==================== 接收端 ====================

#[derive(Default)]
struct Stats {
    copied: u64,
    skipped: u64,
    failed: u64,
    bytes: u64,
}

fn recv_file(
    rd: &mut BufReader<TcpStream>,
    wr: &mut BufWriter<TcpStream>,
    dest: &Path,
    root: &str,
    rel: &str,
    size: u64,
    mtime: u64,
    st: &mut Stats,
    prog: &mut Progress,
    failed: &mut Vec<(String, String)>,
) -> io::Result<()> {
    let base = dest.join(root);
    let final_path = base.join(rel);
    let mut part_os = final_path.as_os_str().to_os_string();
    part_os.push(".lxferpart");
    let part_path = PathBuf::from(part_os);

    // 1) 已完整存在 -> 跳过
    let mut skip = false;
    if let Ok(md) = fs::metadata(&final_path) {
        if md.is_file() && md.len() == size {
            let diff = if mtime > mtime_of(&md) { mtime - mtime_of(&md) } else { mtime_of(&md) - mtime };
            if diff <= 2 {
                skip = true;
            }
        }
    }
    if skip {
        send_line(wr, "SKIP")?;
        st.skipped += 1;
        prog.done_file();
        return Ok(());
    }

    // 2) 决定续传偏移
    let mut off = 0u64;
    if let Ok(md) = fs::metadata(&part_path) {
        let plen = md.len();
        if plen > 0 && plen < size {
            off = plen;
        }
    }
    if let Some(p) = final_path.parent() {
        let _ = fs::create_dir_all(p);
    }
    send_line(wr, &format!("GO\t{}", off))?;

    // 3) 收数据帧
    let mut f = OpenOptions::new().create(true).write(true).truncate(false).open(&part_path)?;
    f.seek(SeekFrom::Start(off))?;
    f.set_len(off)?;
    let mut crc = 0xFFFF_FFFFu32;
    let mut got = 0u64;
    let expected = size - off;
    prog.set_current(rel);
    let mut buf = vec![0u8; BUFSZ];
    loop {
        let mut lenb = [0u8; 4];
        rd.read_exact(&mut lenb)?;
        let n = u32::from_be_bytes(lenb) as usize;
        if n == 0 {
            break;
        }
        if n > BUFSZ {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "帧长度异常"));
        }
        rd.read_exact(&mut buf[..n])?;
        f.write_all(&buf[..n])?;
        crc = crc_update(crc, &buf[..n]);
        got += n as u64;
        prog.tick(n as u64);
    }
    f.flush()?;

    // 4) 校验
    let line = read_msg(rd)?;
    let lf = fields(&line);
    let sender_crc: u64 = if lf.len() >= 2 { lf[1].parse().unwrap_or(0) } else { 1 };
    let ok = got == expected && sender_crc == crc_finish(crc) as u64;
    if ok {
        set_mtime(&f, mtime);
        drop(f);
        match fs::rename(&part_path, &final_path) {
            Ok(_) => {
                send_line(wr, "OK")?;
                st.copied += 1;
                st.bytes += expected;
                prog.done_file();
            }
            Err(e) => {
                let _ = fs::remove_file(&part_path);
                send_line(wr, "BAD")?;
                st.failed += 1;
                failed.push((final_path.to_string_lossy().to_string(), format!("改名失败: {}", e)));
                prog.done_file();
            }
        }
    } else {
        drop(f);
        let _ = fs::remove_file(&part_path);
        send_line(wr, "BAD")?;
        st.failed += 1;
        let reason = if got != expected {
            format!("数据不完整: 期望 {} 字节，收到 {}", expected, got)
        } else {
            "CRC 校验不通过".to_string()
        };
        failed.push((final_path.to_string_lossy().to_string(), reason));
        prog.done_file();
    }
    Ok(())
}

fn write_report(dest: &Path, peer: &SocketAddr, st: &Stats, failed: &[(String, String)], elapsed: Duration) -> Option<PathBuf> {
    let name = format!("lxfer-report-{}.txt", now_secs());
    let path = dest.join(&name);
    let mut s = String::new();
    s.push_str("lxfer 传输报告\n");
    s.push_str("====================\n");
    s.push_str(&format!("时间: {}\n", beijing_now()));
    s.push_str(&format!("发送方: {}\n", peer.ip()));
    s.push_str(&format!("保存到: {}\n", dest.to_string_lossy()));
    s.push_str(&format!(
        "结果: 复制 {} 个，跳过 {} 个（已存在且一致），失败 {} 个\n",
        st.copied, st.skipped, st.failed
    ));
    s.push_str(&format!("本次传输: {}\n", fmt_bytes(st.bytes)));
    s.push_str(&format!("耗时: {}, 平均 {:.1} MB/s\n", fmt_dur(elapsed), st.bytes as f64 / elapsed.as_secs_f64().max(0.001) / 1024.0 / 1024.0));
    if failed.is_empty() {
        s.push_str("校验: 全部文件 CRC32 通过 ✅\n");
    } else {
        s.push_str(&format!("失败清单（{} 个）:\n", failed.len()));
        for (p, r) in failed.iter().take(2000) {
            s.push_str(&format!("  - {}  [{}]\n", p, r));
        }
    }
    let mut data = Vec::with_capacity(s.len() + 3);
    data.extend_from_slice(&[0xEF, 0xBB, 0xBF]); // UTF-8 BOM，Windows 记事本才不会认成乱码
    data.extend_from_slice(s.as_bytes());
    if fs::write(&path, &data).is_ok() {
        Some(path)
    } else {
        None
    }
}

fn handle_session(stream: TcpStream, peer: SocketAddr, code: &str, dest_default: Option<PathBuf>, auto: bool) -> io::Result<()> {
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
    let mut rd = BufReader::with_capacity(64 * 1024, stream.try_clone()?);
    let mut wr = BufWriter::with_capacity(64 * 1024, stream.try_clone()?);

    let line = read_msg(&mut rd)?;
    let f = fields(&line);
    if f.is_empty() || f[0] != "HELLO" {
        let _ = send_line(&mut wr, "DENY\t协议错误");
        return Ok(());
    }
    let got_code = f.get(1).cloned().unwrap_or_default();
    let name = f.get(2).cloned().unwrap_or_else(|| "未知设备".to_string());
    if got_code != code {
        let _ = send_line(&mut wr, "DENY\t配对码错误");
        println!("✗ 拒绝 {} 的连接：配对码错误", peer.ip());
        return Ok(());
    }
    println!();
    println!("✓ 发送方: {} ({})", name, peer.ip());

    let dest: PathBuf = if auto {
        dest_default.unwrap_or_else(|| PathBuf::from("lxfer-recv"))
    } else {
        let def = dest_default.map(|p| p.to_string_lossy().to_string()).unwrap_or_else(|| {
            format!("{}", env::current_dir().unwrap_or_else(|_| PathBuf::from(".")).join("lxfer-recv").to_string_lossy())
        });
        let input = ask_default(&format!("保存目录 [默认 {}]: ", def), &def);
        PathBuf::from(input)
    };
    if let Err(e) = fs::create_dir_all(&dest) {
        let _ = send_line(&mut wr, &format!("DENY\t无法创建保存目录: {}", e));
        println!("✗ 无法创建保存目录: {}", e);
        return Ok(());
    }
    send_line(&mut wr, "WELCOME")?;
    println!("接收目录: {}", dest.to_string_lossy());
    println!("开始接收...（Ctrl+C 可中断，下次重跑会自动续传）");

    let start = Instant::now();
    let mut st = Stats::default();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut prog = Progress::new("接收", 0, 0);
    let mut cur_root = String::new();

    let result: io::Result<()> = (|| {
        loop {
            let line = read_msg(&mut rd)?;
            let f = fields(&line);
            if f.is_empty() {
                continue;
            }
            match f[0].as_str() {
                "PLAN" => {
                    let n: u64 = f.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);
                    let b: u64 = f.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                    prog = Progress::new("接收", n, b);
                    println!("发送端计划: {} 个文件，{}", n, fmt_bytes(b));
                }
                "ROOT" => {
                    cur_root = f.get(1).cloned().unwrap_or_default();
                    println!("\n→ 根目录: {}", cur_root);
                }
                "DIR" => {
                    let rel = f.get(1).cloned().unwrap_or_default();
                    let _ = fs::create_dir_all(dest.join(&cur_root).join(rel));
                }
                "FILE" => {
                    if f.len() < 4 {
                        continue;
                    }
                    let rel = f[1].clone();
                    let size: u64 = f[2].parse().unwrap_or(0);
                    let mtime: u64 = f[3].parse().unwrap_or(0);
                    recv_file(&mut rd, &mut wr, &dest, &cur_root, &rel, size, mtime, &mut st, &mut prog, &mut failed)?;
                }
                "DONE" => {
                    send_line(&mut wr, &format!("FINAL\t{}\t{}\t{}\t{}", st.copied, st.skipped, st.failed, st.bytes))?;
                    break;
                }
                _ => {}
            }
        }
        Ok(())
    })();

    prog.finish();
    let elapsed = start.elapsed();
    match result {
        Ok(()) => {
            println!("✓ 接收完成");
            println!(
                "  复制 {} 个 | 跳过 {} 个 | 失败 {} 个 | 共 {} | 耗时 {} | 平均 {:.1} MB/s",
                st.copied,
                st.skipped,
                st.failed,
                fmt_bytes(st.bytes),
                fmt_dur(elapsed),
                st.bytes as f64 / elapsed.as_secs_f64().max(0.001) / 1024.0 / 1024.0
            );
            if failed.is_empty() {
                println!("  校验: 全部 CRC32 通过 ✅");
            } else {
                for (p, r) in failed.iter().take(10) {
                    println!("  ✗ {}  [{}]", p, r);
                }
            }
            if let Some(rp) = write_report(&dest, &peer, &st, &failed, elapsed) {
                println!("  报告: {}", rp.to_string_lossy());
            }
        }
        Err(e) => {
            println!("\n✗ 传输中断: {}", e);
            println!(
                "  已复制 {} 个 | 跳过 {} 个 | 失败 {} 个 | 共 {}",
                st.copied,
                st.skipped,
                st.failed,
                fmt_bytes(st.bytes)
            );
            println!("  重跑一次发送/接收即会自动续传（.lxferpart 文件已保留）");
            let _ = write_report(&dest, &peer, &st, &failed, elapsed);
        }
    }
    Ok(())
}

fn run_recv(port: u16, dest: Option<PathBuf>, auto: bool, once: bool, code_fixed: Option<String>) -> io::Result<()> {
    let listener = TcpListener::bind(("0.0.0.0", port))?;
    let code = code_fixed.unwrap_or_else(gen_code);
    println!("==========================================================");
    println!("  lxfer 接收端（本机 = 保存数据的那台）");
    println!("  本机 IP  : {}", local_ip());
    println!("  端口     : {}", port);
    println!("  配对码   : {}", code);
    println!("==========================================================");
    println!("  在发送端（旧电脑）运行：");
    println!("    lxfer.exe send -to {} -code {}", local_ip(), code);
    println!("----------------------------------------------------------");
    println!("  等待发送方连接...（首次运行若弹出防火墙提示，请点“允许”）");
    loop {
        let (stream, peer) = match listener.accept() {
            Ok(v) => v,
            Err(e) => {
                println!("接受连接失败: {}", e);
                continue;
            }
        };
        let dest_clone = dest.clone();
        match handle_session(stream, peer, &code, dest_clone, auto) {
            Ok(()) => {}
            Err(e) => println!("会话中止: {}", e),
        }
        if once {
            break;
        }
        println!("\n等待下一个发送方连接...");
    }
    Ok(())
}

// ==================== 发送端 ====================

struct SrcTree {
    root: String,
    path: PathBuf,
    dirs: Vec<String>,
    files: Vec<Entry>,
}

fn send_file(
    rd: &mut BufReader<TcpStream>,
    wr: &mut BufWriter<TcpStream>,
    path: &Path,
    rel: &str,
    size: u64,
    mtime: u64,
    st: &mut Stats,
    prog: &mut Progress,
    failed: &mut Vec<(String, String)>,
) -> io::Result<()> {
    send_line(wr, &format!("FILE\t{}\t{}\t{}", esc(rel), size, mtime))?;
    let reply = read_msg(rd)?;
    if reply == "SKIP" {
        st.skipped += 1;
        prog.done_file();
        return Ok(());
    }
    let rf = fields(&reply);
    if rf.is_empty() || rf[0] != "GO" {
        let msg = rf.get(1).cloned().unwrap_or(reply.clone());
        st.failed += 1;
        failed.push((path.to_string_lossy().to_string(), msg));
        prog.done_file();
        return Ok(());
    }
    let off: u64 = rf.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            // 打不开：发一个空数据帧让它结束
            wr.write_all(&0u32.to_be_bytes())?;
            send_line(wr, "CRC\t0")?;
            let _ = read_msg(rd)?;
            st.failed += 1;
            failed.push((path.to_string_lossy().to_string(), format!("打开失败: {}", e)));
            prog.done_file();
            return Ok(());
        }
    };
    if off > 0 {
        f.seek(SeekFrom::Start(off))?;
    }
    let expected = size.saturating_sub(off);
    prog.set_current(rel);
    let mut crc = 0xFFFF_FFFFu32;
    let mut sent = 0u64;
    let mut buf = vec![0u8; BUFSZ];
    let mut read_err: Option<String> = None;
    while sent < expected {
        let want = min(BUFSZ as u64, expected - sent) as usize;
        match f.read(&mut buf[..want]) {
            Ok(0) => {
                read_err = Some("源文件比元数据短".to_string());
                break;
            }
            Ok(n) => {
                wr.write_all(&(n as u32).to_be_bytes())?;
                wr.write_all(&buf[..n])?;
                crc = crc_update(crc, &buf[..n]);
                sent += n as u64;
                prog.tick(n as u64);
            }
            Err(e) => {
                read_err = Some(format!("读取失败: {}", e));
                break;
            }
        }
    }
    wr.write_all(&0u32.to_be_bytes())?;
    send_line(wr, &format!("CRC\t{}", crc_finish(crc)))?;
    let ack = read_msg(rd)?;
    if ack == "OK" && read_err.is_none() {
        st.copied += 1;
        st.bytes += expected;
    } else {
        st.failed += 1;
        let reason = read_err.unwrap_or_else(|| "接收端校验失败".to_string());
        failed.push((path.to_string_lossy().to_string(), reason));
    }
    prog.done_file();
    Ok(())
}

fn run_send(host: &str, port: u16, code: &str, srcs: &[String]) -> io::Result<()> {
    // 1) 先扫描，统计总量
    let mut trees: Vec<SrcTree> = Vec::new();
    for s in srcs {
        let p = PathBuf::from(s);
        if !p.exists() {
            println!("✗ 路径不存在，跳过: {}", s);
            continue;
        }
        if !p.is_dir() {
            println!("✗ 不是目录，跳过: {}", s);
            continue;
        }
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        println!("扫描 {} ...", p.to_string_lossy());
        walk_dir(&p, &p, &mut dirs, &mut files);
        trees.push(SrcTree { root: root_name(&p), path: p.clone(), dirs, files });
    }
    if trees.is_empty() {
        println!("没有可发送的目录");
        return Ok(());
    }
    let total_files: u64 = trees.iter().map(|t| t.files.len() as u64).sum();
    let total_bytes: u64 = trees.iter().flat_map(|t| t.files.iter()).map(|f| f.size).sum();
    println!("共 {} 个文件，{}", total_files, fmt_bytes(total_bytes));

    // 2) 连接
    let addr = format!("{}:{}", host, port);
    println!("连接 {} ...", addr);
    let stream = TcpStream::connect(&addr)?;
    stream.set_nodelay(true).ok();
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();
    let mut rd = BufReader::with_capacity(64 * 1024, stream.try_clone()?);
    let mut wr = BufWriter::with_capacity(64 * 1024, stream.try_clone()?);
    send_line(&mut wr, &format!("HELLO\t{}\t{}", esc(code), esc(&hostname())))?;
    let resp = read_msg(&mut rd)?;
    if !resp.starts_with("WELCOME") {
        let rf = fields(&resp);
        println!("✗ 被接收端拒绝: {}", rf.get(1).cloned().unwrap_or(resp));
        return Ok(());
    }
    println!("✓ 已连接，开始发送");
    send_line(&mut wr, &format!("PLAN\t{}\t{}", total_files, total_bytes))?;

    // 3) 发送
    let start = Instant::now();
    let mut st = Stats::default();
    let mut failed: Vec<(String, String)> = Vec::new();
    let mut prog = Progress::new("发送", total_files, total_bytes);
    let mut result: io::Result<()> = Ok(());
    for t in &trees {
        if let Err(e) = send_line(&mut wr, &format!("ROOT\t{}", esc(&t.root))) {
            result = Err(e);
            break;
        }
        let mut derr = None;
        for d in &t.dirs {
            if let Err(e) = send_line(&mut wr, &format!("DIR\t{}", esc(d))) {
                derr = Some(e);
                break;
            }
        }
        if let Some(e) = derr {
            result = Err(e);
            break;
        }
        for e in &t.files {
            if let Err(err) = send_file(&mut rd, &mut wr, &t.path.join(&e.rel), &e.rel, e.size, e.mtime, &mut st, &mut prog, &mut failed) {
                result = Err(err);
                break;
            }
        }
        if result.is_err() {
            break;
        }
    }
    prog.finish();
    if let Err(e) = result {
        println!("✗ 传输中断: {}", e);
        println!("  已发 {} 个 | 跳过 {} 个 | 失败 {} 个", st.copied, st.skipped, st.failed);
        println!("  重新运行即可续传");
        return Ok(());
    }
    send_line(&mut wr, &format!("DONE\t{}\t{}", total_files, total_bytes))?;
    let fin = read_msg(&mut rd)?;
    let ff = fields(&fin);
    let elapsed = start.elapsed();

    println!("✓ 发送完成");
    println!(
        "  发送 {} 个 | 跳过 {} 个（已存在） | 失败 {} 个 | 共 {} | 耗时 {} | 平均 {:.1} MB/s",
        st.copied,
        st.skipped,
        st.failed,
        fmt_bytes(st.bytes),
        fmt_dur(elapsed),
        st.bytes as f64 / elapsed.as_secs_f64().max(0.001) / 1024.0 / 1024.0
    );
    if ff.len() >= 5 {
        println!(
            "  接收端报告: 复制 {} | 跳过 {} | 失败 {} | 共 {}",
            ff[1], ff[2], ff[3], fmt_bytes(ff[4].parse().unwrap_or(0))
        );
    }
    if !failed.is_empty() {
        println!("  本端失败清单（前 10）:");
        for (p, r) in failed.iter().take(10) {
            println!("    ✗ {}  [{}]", p, r);
        }
    }
    Ok(())
}

// ==================== 入口 ====================

fn print_help() {
    println!("lxfer v0.1 —— 局域网搬家 / 备份（原型）");
    println!();
    println!("用法:");
    println!("  lxfer.exe                                   交互菜单（推荐，双击运行）");
    println!("  lxfer.exe recv [-p 8787] [-d 保存目录] [-y] [-once]");
    println!("  lxfer.exe send -to 192.168.10.30 [-p 8787] -code 482913 -src \"D:\\\" -src \"E:\\\"");
    println!();
    println!("说明:");
    println!("  recv  在“保存数据”的电脑上运行，会显示 6 位配对码");
    println!("  send  在“有数据”的电脑上运行，输入接收端 IP 和配对码");
    println!("  -y    接收端不询问保存目录，直接用 -d 指定的目录");
    println!("  -once 接收一次后退出（默认一直等待）");
    println!("  -code 接收端也可用 -code 自定义配对码（默认随机 6 位）");
    println!();
    println!("断点续传: 中途断了直接重跑，已传完的会跳过，传了一半的会接着传。");
}

fn interactive() {
    println!("==========================================================");
    println!("  lxfer v0.1  ——  局域网搬家 / 备份（原型）");
    println!("==========================================================");
    println!("  1) 接收：这台电脑保存数据（在新电脑上运行）");
    println!("  2) 发送：把这台电脑的数据发出去（在旧电脑上运行）");
    println!("  0) 退出");
    let choice = ask("请选择 [1/2/0]: ");
    match choice.trim() {
        "1" => {
            let port: u16 = ask_default("端口 [8787]: ", "8787").parse().unwrap_or(DEF_PORT);
            let dir = ask_default("保存目录（直接回车用当前目录下的 lxfer-recv）: ", "");
            let dest = if dir.trim().is_empty() { None } else { Some(PathBuf::from(dir.trim())) };
            if let Err(e) = run_recv(port, dest, false, false, None) {
                println!("✗ 启动失败: {}", e);
            }
        }
        "2" => {
            let host = ask("接收方 IP（例如 192.168.10.31）: ");
            let host = host.trim().to_string();
            if host.is_empty() {
                println!("没输入 IP，退出");
                return;
            }
            let port: u16 = ask_default("端口 [8787]: ", "8787").parse().unwrap_or(DEF_PORT);
            let code = ask("配对码（接收端屏幕上 6 位数字）: ");
            let srcs_raw = ask("要发送的目录，多个用分号分隔（例如 D:\\;E:\\;F:\\;G:\\）: ");
            let srcs: Vec<String> = srcs_raw
                .split([';', '|'])
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if srcs.is_empty() {
                println!("没有输入目录，退出");
                return;
            }
            if let Err(e) = run_send(&host.trim(), port, code.trim(), &srcs) {
                println!("✗ 发送失败: {}", e);
            }
        }
        _ => {}
    }
    println!();
    let _ = ask("按回车键退出...");
}

pub fn run_cli() {
    unsafe {
        SetConsoleOutputCP(65001);
        SetConsoleCP(65001);
    }
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        interactive();
        return;
    }
    let mode = args[1].as_str();
    let mut port: u16 = DEF_PORT;
    let mut to: Option<String> = None;
    let mut code: Option<String> = None;
    let mut srcs: Vec<String> = Vec::new();
    let mut dest: Option<PathBuf> = None;
    let mut auto = false;
    let mut once = false;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                i += 1;
                port = args.get(i).and_then(|s| s.parse().ok()).unwrap_or(DEF_PORT);
            }
            "-to" | "--to" => {
                i += 1;
                to = args.get(i).cloned();
            }
            "-code" | "--code" => {
                i += 1;
                code = args.get(i).cloned();
            }
            "-src" | "--src" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    for part in v.split([';', '|']) {
                        let p = part.trim();
                        if !p.is_empty() {
                            srcs.push(p.to_string());
                        }
                    }
                }
            }
            "-d" | "--dest" => {
                i += 1;
                dest = args.get(i).map(PathBuf::from);
            }
            "-y" | "--yes" => auto = true,
            "-once" => once = true,
            "-h" | "--help" => {
                print_help();
                return;
            }
            other => {
                println!("未知参数: {}", other);
                print_help();
                return;
            }
        }
        i += 1;
    }
    let r = match mode {
        "recv" | "receive" => run_recv(port, dest, auto, once, code.clone()),
        "send" => {
            let mut host = to.clone();
            if host.is_none() {
                let h = ask("接收方 IP: ");
                if h.trim().is_empty() {
                    print_help();
                    return;
                }
                host = Some(h.trim().to_string());
            }
            let c = match code.clone() {
                Some(c) => c,
                None => ask("配对码: ").trim().to_string(),
            };
            let s = if srcs.is_empty() {
                let raw = ask("要发送的目录，多个用分号分隔: ");
                raw.split([';', '|']).map(|x| x.trim().trim_matches('"').to_string()).filter(|x| !x.is_empty()).collect()
            } else {
                srcs.clone()
            };
            run_send(host.as_deref().unwrap_or("127.0.0.1"), port, &c, &s)
        }
        "help" | "-h" | "--help" | "/?" => {
            print_help();
            return;
        }
        other => {
            println!("未知模式: {}", other);
            print_help();
            return;
        }
    };
    if let Err(e) = r {
        println!("✗ 错误: {}", e);
    }
}
