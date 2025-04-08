import 'dart:typed_data';

import 'package:dart_pg/src/cryptor/symmetric/cast5.dart';
import 'package:dart_pg/src/cryptor/symmetric/idea.dart';
import 'package:pointycastle/export.dart';
import 'package:test/test.dart';

void main() {
  group('CAST5', () {
    _blockCipherTest(
      0,
      CAST5Engine(),
      _kp('0123456712345678234567893456789a'),
      '0123456789abcdef',
      '238b4fe5847e44b2',
    );

    _blockCipherTest(
      1,
      CAST5Engine(),
      _kp('01234567123456782345'),
      '0123456789abcdef',
      'eb6a711a2c02271b',
    );

    _blockCipherTest(
      2,
      CAST5Engine(),
      _kp('0123456712'),
      '0123456789abcdef',
      '7ac816d16e9b302e',
    );
  });

  group('IDEA', () {
    _blockCipherTest(
      0,
      IDEAEngine(),
      _kp('00112233445566778899aabbccddeeff'),
      '000102030405060708090a0b0c0d0e0f',
      'ed732271a7b39f475b4b2b6719f194bf',
    );

    _blockCipherTest(
      1,
      IDEAEngine(),
      _kp('00112233445566778899aabbccddeeff'),
      'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      'b8bc6ed5c899265d2bcfad1fc6d4287d',
    );
  });
}

KeyParameter _kp(String key) {
  return KeyParameter(_uint8ListFromHex(key));
}

void _blockCipherTest(
  int id,
  BlockCipher cipher,
  CipherParameters parameters,
  String input,
  String output,
) {
  test('BlockCipher Test: $id ', () {
    var input0 = _uint8ListFromHex(input);
    var output0 = _uint8ListFromHex(output);

    cipher.init(true, parameters);
    var out = Uint8List(input0.length);
    var p = 0;
    while (p < input0.length) {
      p += cipher.processBlock(input0, p, out, p);
    }

    expect(output0, equals(out), reason: '$id did not match output');

    cipher.init(false, parameters);
    out = Uint8List(output0.length);
    p = 0;
    while (p < output0.length) {
      p += cipher.processBlock(output0, p, out, p);
    }

    expect(input0, equals(out), reason: '$id did not match input');
  });
}

Uint8List _uint8ListFromHex(String hex) {
  hex = hex.replaceAll(RegExp(r'\s'), ''); // remove all whitespace, if any

  var result = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < hex.length; i += 2) {
    var num = hex.substring(i, i + 2);
    var byte = int.parse(num, radix: 16);
    result[i ~/ 2] = byte;
  }
  return result;
}
