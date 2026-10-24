// 协议联调工具：让 Dart 端直接和 Windows 桌面端互通
//   dart run tool/e2e.dart send <ip> <port> <code> <file...>
//   dart run tool/e2e.dart serve <port> <code> <saveDir>
import 'dart:convert';
import 'dart:io';

import 'package:lxfer_mobile/src/proto.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty) {
    stderr.writeln('usage: send <ip> <port> <code> <file...> | serve <port> <code> <saveDir>');
    exit(2);
  }
  final mode = args[0];
  if (mode == 'send') {
    final host = args[1];
    final port = int.parse(args[2]);
    final code = args[3];
    final files = args.sublist(4);
    var last = 0;
    final r = await sendFiles(
      host: host,
      port: port,
      code: code,
      paths: files,
      deviceName: Platform.localHostname.isEmpty ? 'DartClient' : Platform.localHostname,
      onProgress: (p) {
        final now = DateTime.now().millisecondsSinceEpoch;
        if (now - last > 1500) {
          last = now;
          stderr.writeln('  ${p.filesDone}/${p.filesTotal}  ${(p.speed / 1024 / 1024).toStringAsFixed(1)} MB/s  ${p.current}');
        }
      },
    );
    print(jsonEncode({
      'copied': r.copied,
      'skipped': r.skipped,
      'failed': r.failed,
      'bytes': r.bytes,
      'dest': r.dest,
      'error': r.error,
    }));
    exit(r.ok ? 0 : 1);
  } else if (mode == 'serve') {
    final port = int.parse(args[1]);
    final code = args[2];
    final saveDir = args[3];
    lxferDebug = (s) => File('D:/workspace/lxfer/_e2e/dart.log').writeAsStringSync(s + '\n', mode: FileMode.append, flush: true);
    File('D:/workspace/lxfer/_e2e/dart.log').writeAsStringSync('--- start serve port=$port ---\n', flush: true);
    var last = 0;
    final r = await receiveFiles(
      port: port,
      code: code,
      saveDir: saveDir,
      deviceName: 'DartReceiver',
      onProgress: (p) {
        final now = DateTime.now().millisecondsSinceEpoch;
        if (now - last > 1500) {
          last = now;
          stderr.writeln('  ${p.filesDone}/${p.filesTotal}  ${(p.speed / 1024 / 1024).toStringAsFixed(1)} MB/s  ${p.current}');
        }
      },
      onPeer: (ip) => stderr.writeln('  来自 $ip'),
    );
    print(jsonEncode({
      'copied': r.copied,
      'skipped': r.skipped,
      'failed': r.failed,
      'bytes': r.bytes,
      'dest': r.dest,
      'error': r.error,
    }));
    exit(r.ok ? 0 : 1);
  } else {
    stderr.writeln('unknown mode $mode');
    exit(2);
  }
}
