import 'package:flutter_test/flutter_test.dart';
import 'package:lxfer_mobile/main.dart';

void main() {
  testWidgets('首页展示发送/接收入口', (tester) async {
    await tester.pumpWidget(const LxferApp());
    expect(find.text('lxfer'), findsOneWidget);
    expect(find.text('发送文件'), findsOneWidget);
    expect(find.text('接收文件'), findsOneWidget);
  });
}
