import 'package:dart_pg/dart_pg.dart';
import 'package:test/test.dart';

void main() {
  group('A group of tests', () {
    final awesome = OpenPGP();

    setUp(() {
      // Additional setup goes here.
    });

    test('First Test', () {
      expect(awesome.isAwesome, isTrue);
    });
  });
}
