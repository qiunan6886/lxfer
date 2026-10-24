// 联调工具：验证 Dart 端加密与 Windows CNG 完全一致
//   dart run tool/probe.dart gen
//   dart run tool/probe.dart derive <privHex|-> <peerPubHex> <code>
//   dart run tool/probe.dart enc <keyHex> <ctr> <plainHex>
//   dart run tool/probe.dart dec <keyHex> <payloadHex>
import 'dart:convert';
import 'dart:typed_data';

import 'package:lxfer_mobile/src/crypto.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    print('usage: gen | derive <priv|-> <peerPub> <code> | enc <key> <ctr> <plainHex> | dec <key> <payloadHex>');
    return;
  }
  switch (args[0]) {
    case 'gen':
      final c = SessionCrypto.generate();
      print(jsonEncode({
        'pub': hexEncode(c.pubBlob),
        'priv': c.privateD.toRadixString(16),
      }));
      break;
    case 'derive':
      final privHex = args[1];
      final peerPub = args[2];
      final code = args[3];
      final c = privHex == '-'
          ? SessionCrypto.generate()
          : SessionCrypto.fromPrivate(BigInt.parse(privHex, radix: 16));
      final ok = c.derive(peerPub, code);
      print(jsonEncode({
        'ok': ok,
        'pub': hexEncode(c.pubBlob),
        'key': c.keyBytes == null ? '' : hexEncode(c.keyBytes!),
      }));
      break;
    case 'enc':
      final key = hexDecode(args[1])!;
      final ctr = int.parse(args[2]);
      final plain = hexDecode(args[3])!;
      final c = SessionCrypto.fromKey(Uint8List.fromList(key))..sendCtr = ctr;
      print(hexEncode(c.encrypt(Uint8List.fromList(plain))));
      break;
    case 'dec':
      final key = hexDecode(args[1])!;
      final payload = Uint8List.fromList(hexDecode(args[2])!);
      final c = SessionCrypto.fromKey(Uint8List.fromList(key));
      final out = c.decrypt(payload);
      print(out == null ? 'FAIL' : hexEncode(out));
      break;
    default:
      print('unknown: ${args[0]}');
  }
}
