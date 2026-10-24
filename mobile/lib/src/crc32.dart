// CRC32 (IEEE)，与桌面端一致
import 'dart:typed_data';

final Uint32List _table = () {
  final t = Uint32List(256);
  for (var i = 0; i < 256; i++) {
    var c = i;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
    }
    t[i] = c;
  }
  return t;
}();

class Crc32 {
  int _crc = 0xFFFFFFFF;
  void update(List<int> data) {
    var c = _crc;
    for (final b in data) {
      c = _table[(c ^ b) & 0xFF] ^ (c >> 8);
    }
    _crc = c;
  }

  int get value => (~_crc) & 0xFFFFFFFF;
}
