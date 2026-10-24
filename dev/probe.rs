// 联调工具：与桌面端完全相同的 CNG 加密实现，用来和 Dart 端交叉验证
// 用法：
//   probe.exe keygen
//   probe.exe derive <peerPubHex> <code>
//   probe.exe enc <keyHex> <ctr> <plainHex>
//   probe.exe dec <keyHex> <payloadHex>
#![allow(non_snake_case)]
use std::ffi::c_void;

type NT = i32;
type H = *mut c_void;

#[repr(C)]
struct BcryptBuffer {
    cb: u32,
    btype: u32,
    pv: *mut c_void,
}
#[repr(C)]
struct BcryptBufferDesc {
    ver: u32,
    count: u32,
    bufs: *mut BcryptBuffer,
}
#[repr(C)]
struct AuthInfo {
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
    fn BCryptOpenAlgorithmProvider(ph: *mut H, alg: *const u16, imp: *const u16, flags: u32) -> NT;
    fn BCryptCloseAlgorithmProvider(h: H, flags: u32) -> NT;
    fn BCryptGenerateKeyPair(alg: H, ph: *mut H, len: u32, flags: u32) -> NT;
    fn BCryptFinalizeKeyPair(k: H, flags: u32) -> NT;
    fn BCryptExportKey(k: H, exp: H, blob: *const u16, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
    fn BCryptImportKeyPair(alg: H, imp: H, blob: *const u16, ph: *mut H, input: *const u8, cb: u32, flags: u32) -> NT;
    fn BCryptSecretAgreement(priv_k: H, pub_k: H, ph: *mut H, flags: u32) -> NT;
    fn BCryptDeriveKey(secret: H, kdf: *const u16, params: *mut BcryptBufferDesc, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
    fn BCryptDestroySecret(s: H) -> NT;
    fn BCryptDestroyKey(k: H) -> NT;
    fn BCryptSetProperty(obj: H, prop: *const u16, input: *const u8, cb: u32, flags: u32) -> NT;
    fn BCryptGenerateSymmetricKey(alg: H, ph: *mut H, obj: *mut u8, cbobj: u32, secret: *const u8, cb: u32, flags: u32) -> NT;
    fn BCryptEncrypt(k: H, input: *const u8, cb: u32, info: *mut c_void, iv: *mut u8, cbiv: u32, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
    fn BCryptDecrypt(k: H, input: *const u8, cb: u32, info: *mut c_void, iv: *mut u8, cbiv: u32, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
}

fn u16z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
fn hex_enc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn hex_dec(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < b.len() {
        let hi = (b[i] as char).to_digit(16).unwrap() as u8;
        let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn keypair() -> Option<(H, H, Vec<u8>)> {
    unsafe {
        let mut alg: H = std::ptr::null_mut();
        if BCryptOpenAlgorithmProvider(&mut alg, u16z("ECDH_P256").as_ptr(), std::ptr::null(), 0) != 0 {
            return None;
        }
        let mut pk: H = std::ptr::null_mut();
        if BCryptGenerateKeyPair(alg, &mut pk, 256, 0) != 0 || BCryptFinalizeKeyPair(pk, 0) != 0 {
            return None;
        }
        let mut cap = 0u32;
        BCryptExportKey(pk, std::ptr::null_mut(), u16z("ECCPUBLICBLOB").as_ptr(), std::ptr::null_mut(), 0, &mut cap, 0);
        let mut blob = vec![0u8; cap as usize];
        let mut res = 0u32;
        if BCryptExportKey(pk, std::ptr::null_mut(), u16z("ECCPUBLICBLOB").as_ptr(), blob.as_mut_ptr(), cap, &mut res, 0) != 0 {
            return None;
        }
        blob.truncate(res as usize);
        Some((alg, pk, blob))
    }
}

fn derive_key(peer_hex: &str, code: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let peer = hex_dec(peer_hex);
    unsafe {
        let (alg, priv_k, pub_blob) = keypair()?;
        let mut pubk: H = std::ptr::null_mut();
        if BCryptImportKeyPair(alg, std::ptr::null_mut(), u16z("ECCPUBLICBLOB").as_ptr(), &mut pubk, peer.as_ptr(), peer.len() as u32, 0) != 0 {
            return None;
        }
        let mut secret: H = std::ptr::null_mut();
        if BCryptSecretAgreement(priv_k, pubk, &mut secret, 0) != 0 {
            return None;
        }
        let mut sha = u16z("SHA256");
        let mut code_bytes = code.as_bytes().to_vec();
        let mut buf1 = BcryptBuffer {
            cb: (sha.len() * 2) as u32,
            btype: 0,
            pv: sha.as_mut_ptr() as *mut c_void,
        };
        let mut buf2 = BcryptBuffer {
            cb: code_bytes.len() as u32,
            btype: 2, // SECRET_APPEND
            pv: code_bytes.as_mut_ptr() as *mut c_void,
        };
        let mut bufs = [buf1, buf2];
        let mut desc = BcryptBufferDesc { ver: 0, count: 2, bufs: bufs.as_mut_ptr() };
        let mut key = vec![0u8; 32];
        let mut res = 0u32;
        let rc = BCryptDeriveKey(secret, u16z("HASH").as_ptr(), &mut desc, key.as_mut_ptr(), 32, &mut res, 0);
        BCryptDestroySecret(secret);
        BCryptDestroyKey(pubk);
        BCryptDestroyKey(priv_k);
        BCryptCloseAlgorithmProvider(alg, 0);
        if rc != 0 {
            return None;
        }
        Some((pub_blob, key))
    }
}

fn aes_key(key: &[u8]) -> Option<(H, H)> {
    unsafe {
        let mut alg: H = std::ptr::null_mut();
        if BCryptOpenAlgorithmProvider(&mut alg, u16z("AES").as_ptr(), std::ptr::null(), 0) != 0 {
            return None;
        }
        let mode = u16z("ChainingModeGCM");
        if BCryptSetProperty(alg, u16z("ChainingMode").as_ptr(), mode.as_ptr() as *const u8, (mode.len() * 2) as u32, 0) != 0 {
            return None;
        }
        let mut k: H = std::ptr::null_mut();
        if BCryptGenerateSymmetricKey(alg, &mut k, std::ptr::null_mut(), 0, key.as_ptr(), key.len() as u32, 0) != 0 {
            return None;
        }
        Some((alg, k))
    }
}

fn gcm(key: &[u8], ctr: u64, data: &[u8], encrypt: bool, tag_in: Option<&[u8]>) -> Option<Vec<u8>> {
    unsafe {
        let (alg, k) = aes_key(key)?;
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&ctr.to_be_bytes());
        let mut tag = [0u8; 16];
        if let Some(t) = tag_in {
            if t.len() >= 16 {
                tag.copy_from_slice(&t[..16]);
            }
        }
        let mut info = AuthInfo {
            cb_size: std::mem::size_of::<AuthInfo>() as u32,
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
        let mut out = vec![0u8; data.len() + 16];
        let mut written = 0u32;
        let rc = if encrypt {
            BCryptEncrypt(k, data.as_ptr(), data.len() as u32, &mut info as *mut _ as *mut c_void, std::ptr::null_mut(), 0, out.as_mut_ptr(), data.len() as u32, &mut written, 0)
        } else {
            BCryptDecrypt(k, data.as_ptr(), data.len() as u32, &mut info as *mut _ as *mut c_void, std::ptr::null_mut(), 0, out.as_mut_ptr(), data.len() as u32, &mut written, 0)
        };
        BCryptDestroyKey(k);
        BCryptCloseAlgorithmProvider(alg, 0);
        if rc != 0 {
            return None;
        }
        out.truncate(written as usize);
        if encrypt {
            out.extend_from_slice(&tag);
        }
        Some(out)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("usage: keygen | derive <peerPub> <code> | enc <key> <ctr> <plainHex> | dec <key> <payloadHex>");
        return;
    }
    match args[1].as_str() {
        "keygen" => match keypair() {
            Some((alg, pk, blob)) => {
                unsafe {
                    BCryptDestroyKey(pk);
                    BCryptCloseAlgorithmProvider(alg, 0);
                }
                println!("{}", hex_enc(&blob));
            }
            None => println!("FAIL"),
        },
        "derive" => match derive_key(&args[2], &args[3]) {
            Some((pub_blob, key)) => println!("{}\t{}", hex_enc(&pub_blob), hex_enc(&key)),
            None => println!("FAIL"),
        },
        "enc" => {
            let key = hex_dec(&args[2]);
            let ctr: u64 = args[3].parse().unwrap_or(0);
            let plain = hex_dec(&args[4]);
            match gcm(&key, ctr, &plain, true, None) {
                Some(ct) => {
                    let mut payload = ctr.to_be_bytes().to_vec();
                    payload.extend_from_slice(&ct);
                    println!("{}", hex_enc(&payload));
                }
                None => println!("FAIL"),
            }
        }
        "dec" => {
            let key = hex_dec(&args[2]);
            let payload = hex_dec(&args[3]);
            if payload.len() < 24 {
                println!("FAIL");
                return;
            }
            let ctr = u64::from_be_bytes([payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6], payload[7]]);
            match gcm(&key, ctr, &payload[8..payload.len() - 16], false, Some(&payload[payload.len() - 16..])) {
                Some(pt) => println!("{}", hex_enc(&pt)),
                None => println!("FAIL"),
            }
        }
        other => println!("unknown {}", other),
    }
}
