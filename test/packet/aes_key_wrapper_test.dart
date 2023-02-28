import 'dart:typed_data';

import 'package:dart_pg/src/packet/key/aes_key_wrapper.dart';
import 'package:test/test.dart';

void main() {
  group('AES Key Wrap & Key Unwrap', () {
    final key128 = Uint8List.fromList([
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
      0x08,
      0x09,
      0x0a,
      0x0b,
      0x0c,
      0x0d,
      0x0e,
      0x0f,
    ]);
    final key192 = Uint8List.fromList([
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
      0x08,
      0x09,
      0x0a,
      0x0b,
      0x0c,
      0x0d,
      0x0e,
      0x0f,
      0x10,
      0x11,
      0x12,
      0x13,
      0x14,
      0x15,
      0x16,
      0x17,
    ]);
    final key256 = Uint8List.fromList([
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
      0x08,
      0x09,
      0x0a,
      0x0b,
      0x0c,
      0x0d,
      0x0e,
      0x0f,
      0x10,
      0x11,
      0x12,
      0x13,
      0x14,
      0x15,
      0x16,
      0x17,
      0x18,
      0x19,
      0x1a,
      0x1b,
      0x1c,
      0x1d,
      0x1e,
      0x1f,
    ]);

    final keyData128 = Uint8List.fromList([
      0x00,
      0x11,
      0x22,
      0x33,
      0x44,
      0x55,
      0x66,
      0x77,
      0x88,
      0x99,
      0xaa,
      0xbb,
      0xcc,
      0xdd,
      0xee,
      0xff,
    ]);
    final keyData192 = Uint8List.fromList([
      0x00,
      0x11,
      0x22,
      0x33,
      0x44,
      0x55,
      0x66,
      0x77,
      0x88,
      0x99,
      0xaa,
      0xbb,
      0xcc,
      0xdd,
      0xee,
      0xff,
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
    ]);
    final keyData256 = Uint8List.fromList([
      0x00,
      0x11,
      0x22,
      0x33,
      0x44,
      0x55,
      0x66,
      0x77,
      0x88,
      0x99,
      0xaa,
      0xbb,
      0xcc,
      0xdd,
      0xee,
      0xff,
      0x00,
      0x01,
      0x02,
      0x03,
      0x04,
      0x05,
      0x06,
      0x07,
      0x08,
      0x09,
      0x0a,
      0x0b,
      0x0c,
      0x0d,
      0x0e,
      0x0f,
    ]);

    test('128-bit test', () {
      final wrappedKey = AesKeyWrapper.wrap(key128, keyData128);
      var keyData = AesKeyWrapper.unwrap(key128, wrappedKey);
      expect(keyData, equals(keyData128));
    });

    test('192-bit test', () {
      final wrappedKey128 = AesKeyWrapper.wrap(key192, keyData128);
      var unwrappedKey128 = AesKeyWrapper.unwrap(key192, wrappedKey128);
      expect(unwrappedKey128, equals(keyData128));

      final wrappedKey192 = AesKeyWrapper.wrap(key192, keyData192);
      var unwrappedKey192 = AesKeyWrapper.unwrap(key192, wrappedKey192);
      expect(unwrappedKey192, equals(keyData192));
    });

    test('256-bit test', () {
      final wrappedKey128 = AesKeyWrapper.wrap(key256, keyData128);
      var unwrappedKey128 = AesKeyWrapper.unwrap(key256, wrappedKey128);
      expect(unwrappedKey128, equals(keyData128));

      final wrappedKey192 = AesKeyWrapper.wrap(key256, keyData192);
      var unwrappedKey192 = AesKeyWrapper.unwrap(key256, wrappedKey192);
      expect(unwrappedKey192, equals(keyData192));

      final wrappedKey256 = AesKeyWrapper.wrap(key256, keyData256);
      var unwrappedKey256 = AesKeyWrapper.unwrap(key256, wrappedKey256);
      expect(unwrappedKey256, equals(keyData256));
    });
  });
}
