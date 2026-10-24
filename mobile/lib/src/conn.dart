// 与桌面端一致的加密记录层：
//   明文模式：控制行以 \n 结尾；数据帧 = u32(len) + bytes（len=0 表示文件结束）
//   加密模式：每条消息一个密文记录 = u32(payloadLen) + payload(ctr/ct/tag)；
//             控制行在密文里带 \n；数据帧是独立记录，空明文代表文件结束
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'crypto.dart';

class Conn {
  final Socket _sock;
  final _Reader _rd;
  SessionCrypto? crypto;
  final List<int> _lineBuf = [];
  bool _closed = false;

  Conn._(this._sock, this._rd);

  static Future<Conn> connect(String host, int port) async {
    final s = await Socket.connect(host, port, timeout: const Duration(seconds: 10));
    s.setOption(SocketOption.tcpNoDelay, true);
    return Conn._(s, _Reader(s));
  }

  static Conn fromSocket(Socket s) {
    s.setOption(SocketOption.tcpNoDelay, true);
    return Conn._(s, _Reader(s));
  }

  bool get secure => crypto != null;

  void enableCrypto(SessionCrypto c) => crypto = c;

  Future<void> _sendRecord(Uint8List payload) async {
    final head = Uint8List(4);
    ByteData.view(head.buffer).setUint32(0, payload.length);
    _sock.add(head);
    _sock.add(payload);
  }

  Future<void> putLine(String line) async {
    final raw = Uint8List.fromList(utf8.encode('$line\n'));
    final c = crypto;
    if (c == null) {
      _sock.add(raw);
    } else {
      await _sendRecord(c.encrypt(raw));
    }
  }

  Future<void> sendLine(String line) async {
    await putLine(line);
    await flush();
  }

  Future<void> flush() => _sock.flush();

  Future<Uint8List> _readRecord() async {
    final head = await _rd.readExact(4);
    final n = ByteData.view(head.buffer, head.offsetInBytes).getUint32(0);
    if (n == 0 || n > 16 * 1024 * 1024) {
      throw const FormatException('记录长度异常');
    }
    return _rd.readExact(n);
  }

  Future<String> readMsg() async {
    while (true) {
      final idx = _lineBuf.indexOf(10);
      if (idx >= 0) {
        final line = utf8.decode(Uint8List.fromList(_lineBuf.sublist(0, idx)), allowMalformed: true);
        _lineBuf.removeRange(0, idx + 1);
        return line.endsWith('\r') ? line.substring(0, line.length - 1) : line;
      }
      final c = crypto;
      if (c == null) {
        _lineBuf.addAll(await _rd.readUntil(10));
      } else {
        final rec = await _readRecord();
        final pt = c.decrypt(rec);
        if (pt == null) throw const FormatException('解密失败');
        _lineBuf.addAll(pt);
      }
    }
  }

  Future<void> writeFrame(List<int> data) async {
    final c = crypto;
    if (c == null) {
      final head = Uint8List(4);
      ByteData.view(head.buffer).setUint32(0, data.length);
      _sock.add(head);
      if (data.isNotEmpty) _sock.add(data);
    } else {
      await _sendRecord(c.encrypt(Uint8List.fromList(data)));
    }
  }

  /// 返回 null 表示文件结束标记
  Future<Uint8List?> readFrame() async {
    final c = crypto;
    if (c == null) {
      final head = await _rd.readExact(4);
      final n = ByteData.view(head.buffer, head.offsetInBytes).getUint32(0);
      if (n == 0) return null;
      if (n > 8 * 1024 * 1024) throw const FormatException('帧长度异常');
      return _rd.readExact(n);
    }
    final rec = await _readRecord();
    final pt = c.decrypt(rec);
    if (pt == null) throw const FormatException('数据解密失败');
    return pt.isEmpty ? null : pt;
  }

  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    try {
      await _sock.flush();
    } catch (_) {}
    try {
      await _sock.close();
    } catch (_) {}
  }

  void destroy() {
    if (_closed) return;
    _closed = true;
    try {
      _sock.destroy();
    } catch (_) {}
  }
}

class _Reader {
  final StreamIterator<List<int>> _it;
  final List<int> _buf = [];
  int _pos = 0;
  _Reader(Stream<List<int>> s) : _it = StreamIterator(s);

  Future<bool> _fill() async {
    if (!await _it.moveNext()) return false;
    _buf.addAll(_it.current);
    return true;
  }

  Future<Uint8List> readExact(int n) async {
    while (_buf.length - _pos < n) {
      if (!await _fill()) throw const SocketException('连接已断开');
    }
    final out = Uint8List.fromList(_buf.sublist(_pos, _pos + n));
    _pos += n;
    _compact();
    return out;
  }

  Future<List<int>> readUntil(int byte) async {
    while (true) {
      for (var i = _pos; i < _buf.length; i++) {
        if (_buf[i] == byte) {
          final out = _buf.sublist(_pos, i + 1);
          _pos = i + 1;
          _compact();
          return out;
        }
      }
      if (!await _fill()) throw const SocketException('连接已断开');
    }
  }

  void _compact() {
    if (_pos > 256 * 1024) {
      _buf.removeRange(0, _pos);
      _pos = 0;
    }
  }
}
