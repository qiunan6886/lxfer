// 与桌面端 lxfer 完全兼容的批量传输协议（加密握手 + 多连接接收 + 断点续传）
import 'dart:async';
import 'dart:io';
import 'dart:math';

import 'conn.dart';

import 'crc32.dart';
import 'crypto.dart';

void Function(String)? lxferDebug;

const int _batchFiles = 32;
const int _batchBytes = 16 * 1024 * 1024;
const int _chunk = 1024 * 1024;

String esc(String s) => s
    .replaceAll('\\', r'\\')
    .replaceAll('\t', r'\t')
    .replaceAll('\n', r'\n')
    .replaceAll('\r', r'\r');

String unesc(String s) {
  final sb = StringBuffer();
  for (var i = 0; i < s.length; i++) {
    final c = s[i];
    if (c == '\\' && i + 1 < s.length) {
      final n = s[++i];
      switch (n) {
        case '\\':
          sb.write('\\');
          break;
        case 't':
          sb.write('\t');
          break;
        case 'n':
          sb.write('\n');
          break;
        case 'r':
          sb.write('\r');
          break;
        default:
          sb.write(n);
      }
    } else {
      sb.write(c);
    }
  }
  return sb.toString();
}

class Progress {
  int filesDone = 0;
  int filesTotal = 0;
  int bytesDone = 0;
  int bytesTotal = 0;
  String current = '';
  double speed = 0;
  int eta = 0;
  bool secure = false;
  int workers = 1;
}

typedef ProgressFn = void Function(Progress p);

class XferResult {
  int copied = 0;
  int skipped = 0;
  int failed = 0;
  int bytes = 0;
  String dest = '';
  String? error;
  bool get ok => error == null;
}

class _Cancelled implements Exception {
  const _Cancelled();
}

String _jobId() =>
    '${DateTime.now().millisecondsSinceEpoch}-${Random().nextInt(1 << 30)}';

class _Entry {
  final String path;
  final String rel;
  final int size;
  final int mtime;
  _Entry(this.path, this.rel, this.size, this.mtime);
}

// ============================ 发送（手机 → 电脑） ============================

Future<XferResult> sendFiles({
  required String host,
  required int port,
  required String code,
  required List<String> paths,
  required String deviceName,
  required ProgressFn onProgress,
  String root = '手机',
  bool Function()? cancelled,
}) async {
  final result = XferResult();
  final entries = <_Entry>[];
  for (final p in paths) {
    final f = File(p);
    if (!f.existsSync()) continue;
    final st = f.statSync();
    final name = p.split(RegExp(r'[\\/]')).last;
    entries.add(_Entry(p, name, st.size, st.modified.millisecondsSinceEpoch ~/ 1000));
  }
  if (entries.isEmpty) {
    result.error = '没有可发送的文件';
    return result;
  }
  final totalBytes = entries.fold<int>(0, (a, e) => a + e.size);
  final prog = Progress()
    ..filesTotal = entries.length
    ..bytesTotal = totalBytes
    ..current = '正在连接电脑…';
  onProgress(prog);

  Conn? conn;
  try {
    conn = await Conn.connect(host, port);
    final crypto = SessionCrypto.generate();
    await conn.sendLine([
      'HELLO2',
      esc(code),
      esc(deviceName),
      esc(_jobId()),
      '0',
      '1',
      hexEncode(crypto.pubBlob),
      '$totalBytes',
      '0',
      '',
    ].join('\t'));
    final welcome = await conn.readMsg();
    final wf = welcome.split('\t');
    if (wf.isEmpty || wf[0] != 'WELCOME') {
      result.error = wf.length > 1 ? unesc(wf[1]) : '被接收端拒绝';
      return result;
    }
    final enc = wf.length > 1 && wf[1] == '1';
    if (enc) {
      final peerPub = wf.length > 2 ? wf[2] : '';
      if (!crypto.derive(peerPub, code)) {
        result.error = '加密协商失败';
        return result;
      }
      conn.enableCrypto(crypto);
      prog.secure = true;
    }
    await conn.sendLine('PLAN\t${entries.length}\t$totalBytes');
    await conn.sendLine('ROOT\t${esc(root)}');

    var fileIdx = 0;
    var bytesDone = 0;
    var copied = 0;
    var skipped = 0;
    var copiedBytes = 0;
    final sw = Stopwatch()..start();
    while (fileIdx < entries.length) {
      if (cancelled?.call() ?? false) throw const _Cancelled();
      final batch = <_Entry>[];
      var batchBytes = 0;
      while (fileIdx < entries.length &&
          batch.length < _batchFiles &&
          (batch.isEmpty || batchBytes + entries[fileIdx].size <= _batchBytes)) {
        batchBytes += entries[fileIdx].size;
        batch.add(entries[fileIdx]);
        fileIdx++;
      }
      await conn.putLine('BATCH\t${batch.length}');
      for (final e in batch) {
        await conn.putLine('F\t${esc(e.rel)}\t${e.size}\t${e.mtime}');
      }
      await conn.putLine('BEND');
      await conn.flush();

      final decHead = await conn.readMsg();
      if (!decHead.startsWith('DEC')) throw const FormatException('接收端响应异常');
      final decisions = <int?>[];
      for (var i = 0; i < batch.length; i++) {
        final l = await conn.readMsg();
        final p = l.split('\t');
        if (p[0] == 'G') {
          decisions.add(p.length > 1 ? (int.tryParse(p[1]) ?? 0) : 0);
        } else {
          decisions.add(null);
        }
      }
      await conn.readMsg(); // DEND

      for (var i = 0; i < batch.length; i++) {
        if (cancelled?.call() ?? false) throw const _Cancelled();
        final e = batch[i];
        final off = decisions[i];
        if (off == null) {
          skipped++;
          prog.filesDone++;
          onProgress(prog);
          continue;
        }
        prog.current = e.rel;
        final raf = await File(e.path).open();
        final crc = Crc32();
        var sent = 0;
        final expected = e.size - off;
        try {
          if (off > 0) await raf.setPosition(off);
          while (sent < expected) {
            if (cancelled?.call() ?? false) throw const _Cancelled();
            final want = min(_chunk, expected - sent);
            final data = await raf.read(want);
            if (data.isEmpty) break;
            await conn.writeFrame(data);
            crc.update(data);
            sent += data.length;
            bytesDone += data.length;
            prog.bytesDone = bytesDone;
            prog.speed = bytesDone / max(1, sw.elapsedMilliseconds / 1000.0);
            prog.eta = prog.speed > 1
                ? ((totalBytes - bytesDone) / prog.speed).round()
                : 0;
            onProgress(prog);
          }
        } finally {
          await raf.close();
        }
        await conn.writeFrame(const []);
        await conn.putLine('C\t${crc.value}');
        copied++;
        copiedBytes += expected;
        prog.filesDone++;
      }
      await conn.flush();

      final rline = await conn.readMsg();
      final rf = rline.split('\t');
      final nf = rf.length > 1 ? (int.tryParse(rf[1]) ?? 0) : 0;
      for (var i = 0; i < nf; i++) {
        await conn.readMsg();
      }
      onProgress(prog);
    }

    await conn.sendLine(
        'DONE\t${entries.length}\t$totalBytes\t$copied\t$skipped\t${entries.length - copied - skipped}\t$copiedBytes');
    final fin = await conn.readMsg();
    final ff = fin.split('\t');
    if (ff.isNotEmpty && ff[0] == 'FINAL') {
      if (ff.length > 1) result.copied = int.tryParse(ff[1]) ?? copied;
      if (ff.length > 2) result.skipped = int.tryParse(ff[2]) ?? skipped;
      if (ff.length > 3) result.failed = int.tryParse(ff[3]) ?? 0;
      if (ff.length > 4) result.bytes = int.tryParse(ff[4]) ?? copiedBytes;
      if (ff.length > 5) result.dest = unesc(ff[5]);
    } else {
      result
        ..copied = copied
        ..skipped = skipped
        ..failed = entries.length - copied - skipped
        ..bytes = copiedBytes;
    }
  } on _Cancelled {
    result.error = '已取消';
  } catch (e) {
    result.error = e.toString();
  } finally {
    await conn?.close();
  }
  return result;
}

// ============================ 接收（电脑 → 手机） ============================

class _RecvJob {
  final String code;
  final String saveDir;
  final Progress prog = Progress();
  final List<bool> done = [];
  final List<String> errors = [];
  int workers = 1;
  int copied = 0;
  int skipped = 0;
  int failed = 0;
  int bytes = 0;
  final Stopwatch sw = Stopwatch()..start();
  final Completer<XferResult> completer = Completer<XferResult>();

  _RecvJob(this.code, this.saveDir);
}

Future<XferResult> receiveFiles({
  required int port,
  required String code,
  required String saveDir,
  required String deviceName,
  required ProgressFn onProgress,
  void Function(String peerIp)? onPeer,
  bool Function()? cancelled,
}) async {
  final job = _RecvJob(code, saveDir);
  final server = await ServerSocket.bind(InternetAddress.anyIPv4, port);
  final sub = server.listen((sock) {
    _handleSession(sock, job, deviceName, onProgress, onPeer, cancelled);
  });
  try {
    return await job.completer.future.timeout(
      const Duration(hours: 6),
      onTimeout: () => XferResult()..error = '等待超时（没有发送端连接）',
    );
  } finally {
    await sub.cancel();
    await server.close();
  }
}

Future<void> _handleSession(
  Socket sock,
  _RecvJob job,
  String deviceName,
  ProgressFn onProgress,
  void Function(String)? onPeer,
  bool Function()? cancelled,
) async {
  final conn = Conn.fromSocket(sock);
  var widx = 0;
  try {
    final hello = await conn.readMsg();
    final f = hello.split('\t');
    if (f.length < 8 || f[0] != 'HELLO2') {
      await conn.sendLine('DENY\t协议不匹配，请把电脑端升级到同一版本');
      return;
    }
    if (unesc(f[1]) != job.code) {
      await conn.sendLine('DENY\t配对码错误');
      return;
    }
    widx = int.tryParse(f[4]) ?? 0;
    final count = max(1, int.tryParse(f[5]) ?? 1);
    if (job.done.isEmpty) {
      job.workers = count;
      job.done.addAll(List<bool>.filled(count, false));
      job.prog.workers = count;
    }
    onPeer?.call(sock.remoteAddress.address);
    lxferDebug?.call('HELLO2 widx=$widx count=$count fields=${f.length}');

    final crypto = SessionCrypto.generate();
    final ok = crypto.derive(f[6], job.code);
    await conn.sendLine('WELCOME\t${ok ? 1 : 0}\t${ok ? hexEncode(crypto.pubBlob) : ''}');
    if (ok) {
      conn.enableCrypto(crypto);
      job.prog.secure = true;
    }

    var curRoot = '';
    while (true) {
      if (cancelled?.call() ?? false) throw const _Cancelled();
      final line = await conn.readMsg();
      final p = line.split('\t');
      if (p.isEmpty) continue;
      switch (p[0]) {
        case 'PLAN':
          if (p.length > 2) {
            job.prog.filesTotal += int.tryParse(p[1]) ?? 0;
            job.prog.bytesTotal += int.tryParse(p[2]) ?? 0;
            onProgress(job.prog);
          }
          break;
        case 'ROOT':
          curRoot = unesc(p.length > 1 ? p[1] : '');
          break;
        case 'DIR':
          final rel = unesc(p.length > 1 ? p[1] : '')
              .replaceAll('\\', Platform.pathSeparator);
          try {
            await Directory('${job.saveDir}${Platform.pathSeparator}$curRoot${Platform.pathSeparator}$rel')
                .create(recursive: true);
          } catch (_) {}
          break;
        case 'ABORT':
          _markDone(job, widx, error: '发送方已放弃');
          return;
        case 'BATCH':
          await _recvBatch(conn, job, curRoot, int.tryParse(p.length > 1 ? p[1] : '0') ?? 0,
              onProgress, cancelled);
          break;
        case 'DONE':
          // 计数已按文件逐个累计（_recvBatch），这里直接把本任务汇总回给发送端
          await conn.sendLine('FINAL\t${job.copied}\t${job.skipped}\t${job.failed}\t${job.bytes}\t${esc(job.saveDir)}');
          _markDone(job, widx);
          return;
        default:
          break;
      }
    }
  } on _Cancelled {
    _markDone(job, widx, error: '已取消');
  } catch (e, st) {
    lxferDebug?.call('session error: $e\n$st');
    _markDone(job, widx, error: e.toString());
  } finally {
    await conn.close();
  }
}

void _markDone(_RecvJob job, int widx, {String? error}) {
  if (error != null) job.errors.add(error);
  if (widx >= 0 && widx < job.done.length) job.done[widx] = true;
  final all = job.done.isNotEmpty && job.done.every((d) => d);
  if (all && !job.completer.isCompleted) {
    final r = XferResult()
      ..copied = job.copied
      ..skipped = job.skipped
      ..failed = job.failed + job.errors.length
      ..bytes = job.bytes
      ..dest = job.saveDir;
    if (job.errors.isNotEmpty) r.error = job.errors.first;
    job.completer.complete(r);
  }
}

Future<void> _recvBatch(
  Conn conn,
  _RecvJob job,
  String curRoot,
  int n,
  ProgressFn onProgress,
  bool Function()? cancelled,
) async {
  final base = '${job.saveDir}${Platform.pathSeparator}$curRoot';
  final rels = <String>[];
  final sizes = <int>[];
  final mtimes = <int>[];
  for (var i = 0; i < n; i++) {
    final l = await conn.readMsg();
    final p = l.split('\t');
    if (p.length < 4) {
      rels.add('');
      sizes.add(0);
      mtimes.add(0);
      continue;
    }
    rels.add(unesc(p[1]).replaceAll('\\', Platform.pathSeparator));
    sizes.add(int.tryParse(p[2]) ?? 0);
    mtimes.add(int.tryParse(p[3]) ?? 0);
  }
  await conn.readMsg(); // BEND

  final finals = <File>[];
  final parts = <File>[];
  final offsets = <int>[];
  final skips = <bool>[];
  for (var i = 0; i < n; i++) {
    final safeRel = rels[i].split(Platform.pathSeparator).where((s) => s != '..' && s.isNotEmpty).join(Platform.pathSeparator);
    final finalPath = File('$base${Platform.pathSeparator}$safeRel');
    final partPath = File('${finalPath.path}.lxferpart');
    var skip = false;
    if (finalPath.existsSync() && finalPath.lengthSync() == sizes[i]) skip = true;
    var off = 0;
    if (!skip && partPath.existsSync()) {
      final plen = partPath.lengthSync();
      if (plen > 0 && plen < sizes[i]) off = plen;
    }
    if (!skip) {
      try {
        await finalPath.parent.create(recursive: true);
      } catch (_) {}
    }
    finals.add(finalPath);
    parts.add(partPath);
    offsets.add(off);
    skips.add(skip);
  }

  await conn.putLine('DEC\t$n');
  for (var i = 0; i < n; i++) {
    await conn.putLine(skips[i] ? 'S' : 'G\t${offsets[i]}');
  }
  await conn.putLine('DEND');
  await conn.flush();

  final batchFail = <String>[];
  for (var i = 0; i < n; i++) {
    if (cancelled?.call() ?? false) throw const _Cancelled();
    if (skips[i]) {
      job.skipped++;
      job.prog.filesDone++;
      onProgress(job.prog);
      continue;
    }
    final expected = sizes[i] - offsets[i];
    final raf = await parts[i].open(
      mode: offsets[i] > 0 ? FileMode.append : FileMode.write,
    );
    final crc = Crc32();
    var got = 0;
    job.prog.current = rels[i];
    try {
      while (true) {
        if (cancelled?.call() ?? false) throw const _Cancelled();
        final frame = await conn.readFrame();
        if (frame == null) break;
        await raf.writeFrom(frame);
        crc.update(frame);
        got += frame.length;
        job.prog.bytesDone += frame.length;
        job.prog.speed =
            job.prog.bytesDone / max(1, job.sw.elapsedMilliseconds / 1000.0);
        job.prog.eta = job.prog.speed > 1
            ? ((job.prog.bytesTotal - job.prog.bytesDone) / job.prog.speed).round()
            : 0;
        onProgress(job.prog);
      }
    } finally {
      await raf.close();
    }

    final cLine = await conn.readMsg();
    final cp = cLine.split('\t');
    final senderCrc = cp.length > 1 ? (int.tryParse(cp[1]) ?? -1) : -1;
    if (got == expected && senderCrc == crc.value) {
      try {
        if (mtimes[i] > 0) {
          await parts[i]
              .setLastModified(DateTime.fromMillisecondsSinceEpoch(mtimes[i] * 1000));
        }
        await parts[i].rename(finals[i].path);
        job.copied++;
        job.bytes += expected;
      } catch (_) {
        job.failed++;
        batchFail.add(rels[i]);
      }
    } else {
      try {
        await parts[i].delete();
      } catch (_) {}
      job.failed++;
      batchFail.add(rels[i]);
    }
    job.prog.filesDone++;
    onProgress(job.prog);
  }

  await conn.putLine('R\t${batchFail.length}');
  for (final p in batchFail) {
    await conn.putLine('X\t${esc(p)}\t校验失败');
  }
  await conn.flush();
}
