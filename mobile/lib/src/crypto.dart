// lxfer Android —— 与桌面端完全一致的会话加密
// ECDH P-256 + SHA256(shared || pairingCode) 派生密钥 + AES-256-GCM
import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart';

Uint8List bigIntToBytes(BigInt v, int len) {
  final out = Uint8List(len);
  var x = v;
  final mask = BigInt.from(0xff);
  for (var i = len - 1; i >= 0; i--) {
    out[i] = (x & mask).toInt();
    x = x >> 8;
  }
  return out;
}

BigInt bytesToBigInt(List<int> b) {
  var r = BigInt.zero;
  for (final v in b) {
    r = (r << 8) | BigInt.from(v);
  }
  return r;
}

String hexEncode(List<int> b) {
  final sb = StringBuffer();
  for (final v in b) {
    sb.write(v.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

Uint8List? hexDecode(String s) {
  if (s.isEmpty || s.length.isOdd) return null;
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    final hi = int.tryParse(s[i * 2], radix: 16);
    final lo = int.tryParse(s[i * 2 + 1], radix: 16);
    if (hi == null || lo == null) return null;
    out[i] = (hi << 4) | lo;
  }
  return out;
}

class SessionCrypto {
  final BigInt _d;
  final Uint8List pubBlob; // Windows ECCPUBLICBLOB: magic + cbKey + X(32) + Y(32)
  Uint8List? _aesKey;
  int _sendCtr = 0;

  SessionCrypto._(this._d, this.pubBlob);

  static ECDomainParameters _domain() => ECDomainParameters('prime256v1');

  static SessionCrypto generate() {
    final rnd = FortunaRandom();
    final seed = Uint8List.fromList(
      List<int>.generate(32, (_) => Random.secure().nextInt(256)),
    );
    rnd.seed(KeyParameter(seed));
    final gen = ECKeyGenerator()
      ..init(ParametersWithRandom(ECKeyGeneratorParameters(_domain()), rnd));
    final pair = gen.generateKeyPair();
    final priv = pair.privateKey as ECPrivateKey;
    final pub = pair.publicKey as ECPublicKey;
    final q = pub.Q!;
    final blob = Uint8List(72);
    blob[0] = 0x45; // 'E'
    blob[1] = 0x43; // 'C'
    blob[2] = 0x4B; // 'K'
    blob[3] = 0x31; // '1'
    blob[4] = 32; // cbKey
    blob.setRange(8, 40, bigIntToBytes(q.x!.toBigInteger()!, 32));
    blob.setRange(40, 72, bigIntToBytes(q.y!.toBigInteger()!, 32));
    return SessionCrypto._(priv.d!, blob);
  }

  /// 用对方公钥 + 配对码派生 AES-256 会话密钥
  bool derive(String peerPubHex, String code) {
    final peer = hexDecode(peerPubHex);
    if (peer == null || peer.length < 72) return false;
    final x = bytesToBigInt(peer.sublist(8, 40));
    final y = bytesToBigInt(peer.sublist(40, 72));
    try {
      final curve = _domain().curve!;
      final peerPoint = curve.createPoint(x, y)!;
      final shared = (peerPoint * _d)!;
      final sx = shared.x!.toBigInteger()!;
      final secret = bigIntToBytes(sx, 32);
      final codeBytes = utf8.encode(code);
      final input = Uint8List(secret.length + codeBytes.length)
        ..setRange(0, secret.length, secret)
        ..setRange(secret.length, secret.length + codeBytes.length, codeBytes);
      final digest = SHA256Digest().process(input);
      _aesKey = Uint8List.fromList(digest);
      return true;
    } catch (_) {
      return false;
    }
  }

  bool get ready => _aesKey != null;

  Uint8List _nonce(int ctr) {
    final n = Uint8List(12);
    final bd = ByteData.view(n.buffer);
    bd.setUint64(4, ctr);
    return n;
  }

  /// payload = counter(8, BE) || ciphertext || tag(16)
  Uint8List encrypt(Uint8List plain) {
    final key = _aesKey!;
    final ctr = _sendCtr++;
    final gcm = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, _nonce(ctr), Uint8List(0)));
    final out = gcm.process(plain);
    final payload = Uint8List(8 + out.length);
    ByteData.view(payload.buffer).setUint64(0, ctr);
    payload.setRange(8, payload.length, out);
    return payload;
  }

  Uint8List? decrypt(Uint8List payload) {
    final key = _aesKey;
    if (key == null || payload.length < 24) return null;
    final ctr = ByteData.view(payload.buffer, payload.offsetInBytes).getUint64(0);
    final ct = payload.sublist(8);
    try {
      final gcm = GCMBlockCipher(AESEngine())
        ..init(false, AEADParameters(KeyParameter(key), 128, _nonce(ctr), Uint8List(0)));
      return gcm.process(ct);
    } catch (_) {
      return null;
    }
  }
  // ---- 供联调工具使用 ----
  static SessionCrypto fromKey(Uint8List key) {
    final c = SessionCrypto._(BigInt.zero, Uint8List(0));
    c._aesKey = key;
    return c;
  }

  Uint8List? get keyBytes => _aesKey;
  BigInt get privateD => _d;
  int get sendCtr => _sendCtr;
  set sendCtr(int v) => _sendCtr = v;

  /// 用私钥推导公钥点（联调工具用）
  static Uint8List pubBlobFromPrivate(BigInt d) {
    final domain = _domain();
    final q = (domain.G * d)!;
    final blob = Uint8List(72);
    blob[0] = 0x45;
    blob[1] = 0x43;
    blob[2] = 0x4B;
    blob[3] = 0x31;
    blob[4] = 32;
    blob.setRange(8, 40, bigIntToBytes(q.x!.toBigInteger()!, 32));
    blob.setRange(40, 72, bigIntToBytes(q.y!.toBigInteger()!, 32));
    return blob;
  }

  static SessionCrypto fromPrivate(BigInt d) =>
      SessionCrypto._(d, pubBlobFromPrivate(d));
}