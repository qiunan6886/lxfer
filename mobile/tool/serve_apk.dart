// 极简 HTTP 文件服务器：把 APK 发给同一 WiFi 下的手机
//   dart run tool/serve_apk.dart <目录> <端口>
import 'dart:io';

Future<void> main(List<String> args) async {
  final dir = args.isNotEmpty ? args[0] : '.';
  final port = args.length > 1 ? int.parse(args[1]) : 8099;
  final server = await HttpServer.bind(InternetAddress.anyIPv4, port);
  stdout.writeln('serving $dir on http://0.0.0.0:$port');
  await for (final req in server) {
    try {
      var path = req.uri.path;
      if (path == '/') path = '/index.html';
      final f = File('$dir$path');
      if (!await f.exists()) {
        req.response.statusCode = HttpStatus.notFound;
        await req.response.close();
        continue;
      }
      req.response.headers.contentType = ContentType.binary;
      req.response.headers.set('Content-Disposition',
          'attachment; filename="${path.split('/').last}"');
      await req.response.addStream(f.openRead());
      await req.response.close();
    } catch (_) {
      try {
        req.response.statusCode = 500;
        await req.response.close();
      } catch (_) {}
    }
  }
}
