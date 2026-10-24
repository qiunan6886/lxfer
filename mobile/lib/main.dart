import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:path_provider/path_provider.dart';

import 'src/proto.dart';

void main() {
  runApp(const LxferApp());
}

const _blue = Color(0xFF2F6BFF);

class LxferApp extends StatelessWidget {
  const LxferApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'lxfer 换机助手',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme: ColorScheme.fromSeed(seedColor: _blue, brightness: Brightness.light),
        scaffoldBackgroundColor: const Color(0xFFF3F6FB),
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatelessWidget {
  const HomePage({super.key});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Colors.white,
        elevation: 0,
        title: Row(
          children: [
            Container(
              width: 34,
              height: 34,
              decoration: BoxDecoration(
                gradient: const LinearGradient(colors: [Color(0xFF5B95FF), Color(0xFF2F6BFF)]),
                borderRadius: BorderRadius.circular(11),
              ),
              child: const Icon(Icons.swap_horiz, color: Colors.white, size: 20),
            ),
            const SizedBox(width: 10),
            const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('lxfer', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
                Text('换机助手', style: TextStyle(fontSize: 11, color: Colors.grey)),
              ],
            ),
          ],
        ),
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text('把数据搬到新设备',
                  style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
              const SizedBox(height: 8),
              const Text('同一个 WiFi 下直连传输 · 端到端加密',
                  style: TextStyle(color: Colors.grey)),
              const SizedBox(height: 32),
              _PickCard(
                icon: Icons.upload_rounded,
                title: '发送文件',
                subtitle: '手机上的文件传到电脑',
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const SendPage()),
                ),
              ),
              const SizedBox(height: 16),
              _PickCard(
                icon: Icons.download_rounded,
                title: '接收文件',
                subtitle: '从电脑接收文件到手机',
                onTap: () => Navigator.push(
                  context,
                  MaterialPageRoute(builder: (_) => const ReceivePage()),
                ),
              ),
              const SizedBox(height: 28),
              const Text('v1.0 · 与桌面端 lxfer v3.1 协议一致',
                  style: TextStyle(fontSize: 12, color: Colors.grey)),
            ],
          ),
        ),
      ),
    );
  }
}

class _PickCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  const _PickCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Material(
      color: Colors.white,
      borderRadius: BorderRadius.circular(22),
      child: InkWell(
        borderRadius: BorderRadius.circular(22),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.all(22),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(22),
            border: Border.all(color: const Color(0xFFE6ECF6)),
          ),
          child: Row(
            children: [
              Container(
                width: 56,
                height: 56,
                decoration: BoxDecoration(
                  color: const Color(0xFFEAF1FF),
                  borderRadius: BorderRadius.circular(18),
                ),
                child: Icon(icon, color: _blue, size: 30),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(title,
                        style: const TextStyle(fontSize: 17, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    Text(subtitle, style: const TextStyle(fontSize: 12.5, color: Colors.grey)),
                  ],
                ),
              ),
              const Icon(Icons.chevron_right, color: Colors.grey),
            ],
          ),
        ),
      ),
    );
  }
}

// ============================== 发送 ==============================

class SendPage extends StatefulWidget {
  const SendPage({super.key});

  @override
  State<SendPage> createState() => _SendPageState();
}

class _SendPageState extends State<SendPage> {
  final _ipCtrl = TextEditingController(text: '192.168.10.31');
  final _codeCtrl = TextEditingController();
  final List<File> _files = [];
  bool _running = false;
  bool _cancel = false;
  Progress? _prog;
  XferResult? _result;

  @override
  void dispose() {
    _ipCtrl.dispose();
    _codeCtrl.dispose();
    super.dispose();
  }

  Future<void> _pick() async {
    final picked = await FilePicker.pickFiles();
    if (picked.isEmpty) return;
    setState(() {
      for (final f in picked) {
        final p = f.path;
        if (p != null && !_files.any((e) => e.path == p)) _files.add(File(p));
      }
    });
  }

  Future<void> _start() async {
    if (_files.isEmpty) return _toast('请先选择文件');
    final ip = _ipCtrl.text.trim();
    if (ip.isEmpty) return _toast('请输入电脑的 IP');
    if (_codeCtrl.text.trim().length != 6) return _toast('请输入 6 位配对码');
    setState(() {
      _running = true;
      _cancel = false;
      _result = null;
      _prog = null;
    });
    final r = await sendFiles(
      host: ip,
      port: 8787,
      code: _codeCtrl.text.trim(),
      paths: _files.map((e) => e.path).toList(),
      deviceName: Platform.localHostname.isEmpty ? 'Android' : Platform.localHostname,
      onProgress: (p) {
        if (mounted) setState(() => _prog = p);
      },
      cancelled: () => _cancel,
    );
    if (!mounted) return;
    setState(() {
      _running = false;
      _result = r;
    });
    _showResult(r);
  }

  void _toast(String s) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(s)));
  }

  void _showResult(XferResult r) {
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(r.ok ? '传输完成' : '传输中断'),
        content: Text(r.ok
            ? '发送 ${r.copied} 个文件\n跳过 ${r.skipped} 个\n失败 ${r.failed} 个\n共 ${_fmt(r.bytes)}'
            : (r.error ?? '未知错误')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('好')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('发送文件'), backgroundColor: Colors.white),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _card(
            children: [
              Row(
                children: [
                  const Text('要发送的文件', style: TextStyle(fontWeight: FontWeight.bold)),
                  const Spacer(),
                  TextButton.icon(
                    onPressed: _running ? null : _pick,
                    icon: const Icon(Icons.add, size: 18),
                    label: const Text('选择文件'),
                  ),
                ],
              ),
              if (_files.isEmpty)
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 12),
                  child: Text('还没有选择文件', style: TextStyle(color: Colors.grey)),
                )
              else
                ..._files.map((f) => ListTile(
                      dense: true,
                      contentPadding: EdgeInsets.zero,
                      leading: const Icon(Icons.insert_drive_file_outlined, size: 20),
                      title: Text(f.path.split('/').last,
                          maxLines: 1, overflow: TextOverflow.ellipsis),
                      trailing: Text(_fmt(f.lengthSync()),
                          style: const TextStyle(fontSize: 12, color: Colors.grey)),
                    )),
            ],
          ),
          const SizedBox(height: 14),
          _card(children: [
            const Text('电脑信息', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 12),
            TextField(
              controller: _ipCtrl,
              enabled: !_running,
              decoration: const InputDecoration(
                labelText: '电脑 IP（电脑点“接收数据”后会显示）',
                border: OutlineInputBorder(),
                isDense: true,
              ),
              keyboardType: TextInputType.number,
            ),
            const SizedBox(height: 12),
            TextField(
              controller: _codeCtrl,
              enabled: !_running,
              maxLength: 6,
              keyboardType: TextInputType.number,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              style: const TextStyle(fontSize: 22, letterSpacing: 8, fontWeight: FontWeight.bold),
              textAlign: TextAlign.center,
              decoration: const InputDecoration(
                labelText: '6 位配对码',
                border: OutlineInputBorder(),
                counterText: '',
                isDense: true,
              ),
            ),
          ]),
          const SizedBox(height: 14),
          if (_running || _result != null) _progressCard(),
          const SizedBox(height: 18),
          SizedBox(
            height: 50,
            child: FilledButton(
              onPressed: _running ? null : _start,
              style: FilledButton.styleFrom(
                backgroundColor: _blue,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
              ),
              child: Text(_running ? '传输中…' : '开始传输',
                  style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
            ),
          ),
          if (_running)
            TextButton(
              onPressed: () => setState(() => _cancel = true),
              child: const Text('取消'),
            ),
        ],
      ),
    );
  }

  Widget _progressCard() {
    final p = _prog;
    final total = p?.bytesTotal ?? 0;
    final done = p?.bytesDone ?? 0;
    final pct = total > 0 ? (done / total).clamp(0.0, 1.0) : 0.0;
    return _card(children: [
      Row(
        children: [
          Text('${(pct * 100).toStringAsFixed(1)}%',
              style: const TextStyle(fontSize: 26, fontWeight: FontWeight.bold, color: _blue)),
          const Spacer(),
          if (p != null)
            Text('${(p.speed / 1024 / 1024).toStringAsFixed(1)} MB/s',
                style: const TextStyle(color: Colors.grey)),
        ],
      ),
      const SizedBox(height: 10),
      ClipRRect(
        borderRadius: BorderRadius.circular(8),
        child: LinearProgressIndicator(
          value: pct,
          minHeight: 10,
          backgroundColor: const Color(0xFFE7EEFB),
        ),
      ),
      const SizedBox(height: 10),
      Text(
        p == null
            ? '正在准备…'
            : '${p.filesDone}/${p.filesTotal} 个文件 · ${_fmt(done)} / ${_fmt(total)}'
                '${p.secure ? ' · 加密' : ''}',
        style: const TextStyle(fontSize: 12, color: Colors.grey),
      ),
      if (p != null && p.current.isNotEmpty)
        Padding(
          padding: const EdgeInsets.only(top: 6),
          child: Text(p.current,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
        ),
    ]);
  }
}

// ============================== 接收 ==============================

class ReceivePage extends StatefulWidget {
  const ReceivePage({super.key});

  @override
  State<ReceivePage> createState() => _ReceivePageState();
}

class _ReceivePageState extends State<ReceivePage> {
  String _code = '';
  String _ip = '';
  String _saveDir = '';
  bool _running = false;
  bool _cancel = false;
  Progress? _prog;
  XferResult? _result;
  String? _error;

  @override
  void initState() {
    super.initState();
    _code = (100000 + DateTime.now().microsecondsSinceEpoch % 900000).toString();
    _init();
  }

  Future<void> _init() async {
    try {
      final dir = await getExternalStorageDirectory();
      final base = Directory('${dir!.path}/lxfer');
      await base.create(recursive: true);
      final ips = <String>[];
      for (final ni in await NetworkInterface.list(type: InternetAddressType.IPv4)) {
        for (final a in ni.addresses) {
          if (!a.isLoopback && !a.address.startsWith('169.254.')) ips.add(a.address);
        }
      }
      if (!mounted) return;
      setState(() {
        _saveDir = base.path;
        _ip = ips.isEmpty ? '未知' : ips.first;
      });
    } catch (e) {
      if (mounted) setState(() => _error = e.toString());
    }
  }

  Future<void> _start() async {
    setState(() {
      _running = true;
      _cancel = false;
      _result = null;
      _error = null;
      _prog = null;
    });
    final r = await receiveFiles(
      port: 8787,
      code: _code,
      saveDir: _saveDir,
      deviceName: 'Android',
      onProgress: (p) {
        if (mounted) setState(() => _prog = p);
      },
      cancelled: () => _cancel,
    );
    if (!mounted) return;
    setState(() {
      _running = false;
      _result = r;
    });
    showDialog<void>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
        title: Text(r.ok ? '接收完成' : '接收中断'),
        content: Text(r.ok
            ? '收到 ${r.copied} 个文件\n跳过 ${r.skipped} 个\n失败 ${r.failed} 个\n共 ${_fmt(r.bytes)}\n\n保存到：\n${r.dest}'
            : (r.error ?? '未知错误')),
        actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('好'))],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final p = _prog;
    final total = p?.bytesTotal ?? 0;
    final done = p?.bytesDone ?? 0;
    final pct = total > 0 ? (done / total).clamp(0.0, 1.0) : 0.0;
    return Scaffold(
      appBar: AppBar(title: const Text('接收文件'), backgroundColor: Colors.white),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          _card(children: [
            const Text('配对码', style: TextStyle(fontWeight: FontWeight.bold)),
            const SizedBox(height: 14),
            Center(
              child: Text(
                _code.split('').join(' '),
                style: const TextStyle(
                    fontSize: 38, fontWeight: FontWeight.bold, letterSpacing: 4),
              ),
            ),
            const SizedBox(height: 12),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.wifi, size: 16, color: _blue),
                const SizedBox(width: 6),
                Text('本机 IP：$_ip',
                    style: const TextStyle(fontSize: 13, color: Colors.black87)),
              ],
            ),
            const SizedBox(height: 8),
            const Text(
              '在电脑上选「发送数据」→ 手动输入上面的 IP 和配对码 → 开始传输',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 12, color: Colors.grey),
            ),
            const SizedBox(height: 10),
            Text('保存到：$_saveDir',
                textAlign: TextAlign.center,
                style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
          ]),
          const SizedBox(height: 14),
          if (_running || _result != null)
            _card(children: [
              Row(
                children: [
                  Text('${(pct * 100).toStringAsFixed(1)}%',
                      style: const TextStyle(
                          fontSize: 26, fontWeight: FontWeight.bold, color: _blue)),
                  const Spacer(),
                  if (p != null)
                    Text('${(p.speed / 1024 / 1024).toStringAsFixed(1)} MB/s',
                        style: const TextStyle(color: Colors.grey)),
                ],
              ),
              const SizedBox(height: 10),
              ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: LinearProgressIndicator(
                  value: pct,
                  minHeight: 10,
                  backgroundColor: const Color(0xFFE7EEFB),
                ),
              ),
              const SizedBox(height: 10),
              Text(
                p == null
                    ? '等待电脑连接…'
                    : '${p.filesDone}/${p.filesTotal} 个文件 · ${_fmt(done)} / ${_fmt(total)}'
                        '${p.secure ? ' · 加密' : ''}',
                style: const TextStyle(fontSize: 12, color: Colors.grey),
              ),
              if (p != null && p.current.isNotEmpty)
                Padding(
                  padding: const EdgeInsets.only(top: 6),
                  child: Text(p.current,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
                ),
            ]),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.all(12),
              child: Text(_error!, style: const TextStyle(color: Colors.red)),
            ),
          const SizedBox(height: 18),
          SizedBox(
            height: 50,
            child: FilledButton(
              onPressed: _running ? null : _start,
              style: FilledButton.styleFrom(
                backgroundColor: _blue,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
              ),
              child: Text(_running ? '正在接收…' : '开始接收',
                  style: const TextStyle(fontSize: 15, fontWeight: FontWeight.bold)),
            ),
          ),
          if (_running)
            TextButton(
              onPressed: () => setState(() => _cancel = true),
              child: const Text('取消'),
            ),
        ],
      ),
    );
  }
}

// ============================== 工具 ==============================

Widget _card({required List<Widget> children}) => Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0xFFE6ECF6)),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: children),
    );

String _fmt(int bytes) {
  if (bytes >= 1024 * 1024 * 1024) {
    return '${(bytes / 1024 / 1024 / 1024).toStringAsFixed(2)} GB';
  }
  if (bytes >= 1024 * 1024) return '${(bytes / 1024 / 1024).toStringAsFixed(1)} MB';
  if (bytes >= 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  return '$bytes B';
}
