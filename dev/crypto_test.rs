// crypto_test.rs —— 验证 Windows CNG (bcrypt.dll) 的 ECDH P-256 + AES-256-GCM
// 目的：确认 FFI 结构和调用序列正确，再集成进 lxfer。
#![allow(non_snake_case)]
use std::ffi::c_void;

type NT = i32;
type H = *mut c_void;

#[repr(C)]
struct BcryptBuffer {
    cbBuffer: u32,
    bufferType: u32,
    pvBuffer: *mut c_void,
}
#[repr(C)]
struct BcryptBufferDesc {
    ulVersion: u32,
    cBuffers: u32,
    pBuffers: *mut BcryptBuffer,
}
#[repr(C)]
struct AuthInfo {
    cbSize: u32,
    dwInfoVersion: u32,
    pbNonce: *mut u8,
    cbNonce: u32,
    pbAuthData: *mut u8,
    cbAuthData: u32,
    pbTag: *mut u8,
    cbTag: u32,
    pbMacContext: *mut u8,
    cbMacContext: u32,
    cbAAD: u32,
    cbData: u64,
    dwFlags: u32,
}

#[link(name = "bcrypt")]
extern "system" {
    fn BCryptOpenAlgorithmProvider(ph: *mut H, alg: *const u16, imp: *const u16, flags: u32) -> NT;
    fn BCryptCloseAlgorithmProvider(h: H, flags: u32) -> NT;
    fn BCryptGenerateKeyPair(alg: H, ph: *mut H, len: u32, flags: u32) -> NT;
    fn BCryptFinalizeKeyPair(k: H, flags: u32) -> NT;
    fn BCryptExportKey(k: H, exp: H, blob: *const u16, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
    fn BCryptImportKeyPair(alg: H, imp: H, blob: *const u16, ph: *mut H, input: *const u8, cb: u32, flags: u32) -> NT;
    fn BCryptSecretAgreement(priv_k: H, pub_k: H, phsecret: *mut H, flags: u32) -> NT;
    fn BCryptDeriveKey(secret: H, kdf: *const u16, params: *mut BcryptBufferDesc, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
    fn BCryptDestroySecret(s: H) -> NT;
    fn BCryptDestroyKey(k: H) -> NT;
    fn BCryptSetProperty(obj: H, prop: *const u16, input: *const u8, cb: u32, flags: u32) -> NT;
    fn BCryptGenerateSymmetricKey(alg: H, ph: *mut H, obj: *mut u8, cbobj: u32, secret: *const u8, cb: u32, flags: u32) -> NT;
    fn BCryptEncrypt(k: H, input: *const u8, cb: u32, info: *mut c_void, iv: *mut u8, cbiv: u32, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
    fn BCryptDecrypt(k: H, input: *const u8, cb: u32, info: *mut c_void, iv: *mut u8, cbiv: u32, out: *mut u8, cap: u32, res: *mut u32, flags: u32) -> NT;
}

fn w(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

struct Party {
    alg_ecdh: H,
    priv_key: H,
    pub_blob: Vec<u8>,
    alg_aes: H,
    aes_key: H,
    ctr: u64,
}

impl Party {
    fn new() -> Option<Party> {
        unsafe {
            let mut alg: H = std::ptr::null_mut();
            let r = BCryptOpenAlgorithmProvider(&mut alg, w("ECDH_P256").as_ptr(), std::ptr::null(), 0);
            if r != 0 {
                println!("open ECDH fail {}", r);
                return None;
            }
            let mut pk: H = std::ptr::null_mut();
            let r = BCryptGenerateKeyPair(alg, &mut pk, 256, 0);
            if r != 0 {
                println!("genkey fail {}", r);
                return None;
            }
            let r = BCryptFinalizeKeyPair(pk, 0);
            if r != 0 {
                println!("finalize fail {}", r);
                return None;
            }
            let mut cap = 0u32;
            BCryptExportKey(pk, std::ptr::null_mut(), w("ECCPUBLICBLOB").as_ptr(), std::ptr::null_mut(), 0, &mut cap, 0);
            let mut blob = vec![0u8; cap as usize];
            let mut res = 0u32;
            let r = BCryptExportKey(pk, std::ptr::null_mut(), w("ECCPUBLICBLOB").as_ptr(), blob.as_mut_ptr(), cap, &mut res, 0);
            if r != 0 {
                println!("export fail {}", r);
                return None;
            }
            blob.truncate(res as usize);
            Some(Party { alg_ecdh: alg, priv_key: pk, pub_blob: blob, alg_aes: std::ptr::null_mut(), aes_key: std::ptr::null_mut(), ctr: 0 })
        }
    }

    fn derive(&mut self, peer_blob: &[u8]) -> bool {
        unsafe {
            let mut pubk: H = std::ptr::null_mut();
            let r = BCryptImportKeyPair(self.alg_ecdh, std::ptr::null_mut(), w("ECCPUBLICBLOB").as_ptr(), &mut pubk, peer_blob.as_ptr(), peer_blob.len() as u32, 0);
            if r != 0 {
                println!("import pub fail {}", r);
                return false;
            }
            let mut secret: H = std::ptr::null_mut();
            let r = BCryptSecretAgreement(self.priv_key, pubk, &mut secret, 0);
            if r != 0 {
                println!("secret agreement fail {}", r);
                return false;
            }
            let mut hash_alg = w("SHA256");
            let mut buf = BcryptBuffer { cbBuffer: (hash_alg.len() * 2) as u32, bufferType: 0, pvBuffer: hash_alg.as_mut_ptr() as *mut c_void };
            let mut desc = BcryptBufferDesc { ulVersion: 0, cBuffers: 1, pBuffers: &mut buf };
            let mut key = vec![0u8; 32];
            let mut res = 0u32;
            let r = BCryptDeriveKey(secret, w("HASH").as_ptr(), &mut desc, key.as_mut_ptr(), 32, &mut res, 0);
            BCryptDestroySecret(secret);
            BCryptDestroyKey(pubk);
            if r != 0 {
                println!("derive fail {}", r);
                return false;
            }
            println!("derived key len {}", res);
            // AES-GCM
            let mut alg: H = std::ptr::null_mut();
            let r = BCryptOpenAlgorithmProvider(&mut alg, w("AES").as_ptr(), std::ptr::null(), 0);
            if r != 0 {
                println!("open AES fail {}", r);
                return false;
            }
            let mode = w("ChainingModeGCM");
            let r = BCryptSetProperty(alg, w("ChainingMode").as_ptr(), mode.as_ptr() as *const u8, (mode.len() * 2) as u32, 0);
            if r != 0 {
                println!("set chaining fail {}", r);
                return false;
            }
            let mut k: H = std::ptr::null_mut();
            let r = BCryptGenerateSymmetricKey(alg, &mut k, std::ptr::null_mut(), 0, key.as_ptr(), 32, 0);
            if r != 0 {
                println!("gen sym key fail {}", r);
                return false;
            }
            self.alg_aes = alg;
            self.aes_key = k;
            true
        }
    }

    fn encrypt(&mut self, data: &[u8]) -> Option<(u64, Vec<u8>, Vec<u8>)> {
        unsafe {
            let mut nonce = [0u8; 12];
            let c = self.ctr;
            nonce[4..12].copy_from_slice(&c.to_be_bytes());
            self.ctr += 1;
            let mut tag = [0u8; 16];
            let mut info = AuthInfo {
                cbSize: std::mem::size_of::<AuthInfo>() as u32,
                dwInfoVersion: 1,
                pbNonce: nonce.as_mut_ptr(),
                cbNonce: 12,
                pbAuthData: std::ptr::null_mut(),
                cbAuthData: 0,
                pbTag: tag.as_mut_ptr(),
                cbTag: 16,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: 0,
            };
            let mut out = vec![0u8; data.len()];
            let mut written = 0u32;
            let r = BCryptEncrypt(self.aes_key, data.as_ptr(), data.len() as u32, &mut info as *mut _ as *mut c_void, std::ptr::null_mut(), 0, out.as_mut_ptr(), out.len() as u32, &mut written, 0);
            if r != 0 {
                println!("encrypt fail {}", r);
                return None;
            }
            out.truncate(written as usize);
            Some((c, out, tag.to_vec()))
        }
    }

    fn decrypt(&self, ctr: u64, ct: &[u8], tag: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&ctr.to_be_bytes());
            let mut tagbuf = tag.to_vec();
            let mut info = AuthInfo {
                cbSize: std::mem::size_of::<AuthInfo>() as u32,
                dwInfoVersion: 1,
                pbNonce: nonce.as_mut_ptr(),
                cbNonce: 12,
                pbAuthData: std::ptr::null_mut(),
                cbAuthData: 0,
                pbTag: tagbuf.as_mut_ptr(),
                cbTag: 16,
                pbMacContext: std::ptr::null_mut(),
                cbMacContext: 0,
                cbAAD: 0,
                cbData: 0,
                dwFlags: 0,
            };
            let mut out = vec![0u8; ct.len()];
            let mut written = 0u32;
            let r = BCryptDecrypt(self.aes_key, ct.as_ptr(), ct.len() as u32, &mut info as *mut _ as *mut c_void, std::ptr::null_mut(), 0, out.as_mut_ptr(), out.len() as u32, &mut written, 0);
            if r != 0 {
                println!("decrypt fail {}", r);
                return None;
            }
            out.truncate(written as usize);
            Some(out)
        }
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn main() {
    let mut a = match Party::new() {
        Some(p) => p,
        None => return,
    };
    let mut b = match Party::new() {
        Some(p) => p,
        None => return,
    };
    println!("pub blob len A={} B={}", a.pub_blob.len(), b.pub_blob.len());
    let pa = a.pub_blob.clone();
    let pb = b.pub_blob.clone();
    if !a.derive(&pb) {
        println!("A derive 失败");
        return;
    }
    if !b.derive(&pa) {
        println!("B derive 失败");
        return;
    }
    let msg = b"hello encrypted world, this is a test of AES-256-GCM over ECDH P-256";
    let (ctr, ct, tag) = match a.encrypt(msg) {
        Some(v) => v,
        None => return,
    };
    println!("明文 {} 字节 -> 密文 {} 字节, tag {}", msg.len(), ct.len(), hex(&tag));
    match b.decrypt(ctr, &ct, &tag) {
        Some(pt) => {
            if pt == msg {
                println!("✅ 解密一致，加密链路可用");
            } else {
                println!("❌ 解密内容不一致: {}", String::from_utf8_lossy(&pt));
            }
        }
        None => println!("❌ 解密失败"),
    }
    // 篡改检测
    let mut bad = ct.clone();
    bad[0] ^= 1;
    match b.decrypt(ctr, &bad, &tag) {
        Some(_) => println!("❌ 篡改未被发现（GCM 校验失效）"),
        None => println!("✅ 篡改被 GCM 拒绝（认证有效）"),
    }
}
