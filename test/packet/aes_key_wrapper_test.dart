import 'dart:typed_data';

import 'package:dart_pg/src/packet/key/aes_key_wrapper.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:test/test.dart';

void main() {
  group('AES Key Wrap & Key Unwrap', () {
    final key128 = Uint8List.fromList(List.generate(16, (index) => index));
    final key192 = Uint8List.fromList(List.generate(24, (index) => index));
    final key256 = Uint8List.fromList(List.generate(32, (index) => index));

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
      final wrappedKey128128 = Uint8List.fromList([
        0x1f,
        0xa6,
        0x8b,
        0x0a,
        0x81,
        0x12,
        0xb4,
        0x47,
        0xae,
        0xf3,
        0x4b,
        0xd8,
        0xfb,
        0x5a,
        0x7b,
        0x82,
        0x9d,
        0x3e,
        0x86,
        0x23,
        0x71,
        0xd2,
        0xcf,
        0xe5,
      ]);
      final wrappedKey128 = AesKeyWrapper.wrap(key128, keyData128);
      var unwrappedKey128 = AesKeyWrapper.unwrap(key128, wrappedKey128);

      expect(wrappedKey128, equals(wrappedKey128128));
      expect(unwrappedKey128, equals(keyData128));

      final key = Helper.secureRandom().nextBytes(16);
      final keyData = Helper.secureRandom().nextBytes(32);
      final wrappedKey = AesKeyWrapper.wrap(key, keyData);
      var unwrappedKey = AesKeyWrapper.unwrap(key, wrappedKey);
      expect(unwrappedKey, equals(keyData));
    });

    test('192-bit test', () {
      final wrappedKey128192 = Uint8List.fromList([
        0x96,
        0x77,
        0x8b,
        0x25,
        0xae,
        0x6c,
        0xa4,
        0x35,
        0xf9,
        0x2b,
        0x5b,
        0x97,
        0xc0,
        0x50,
        0xae,
        0xd2,
        0x46,
        0x8a,
        0xb8,
        0xa1,
        0x7a,
        0xd8,
        0x4e,
        0x5d,
      ]);
      final wrappedKey192192 = Uint8List.fromList([
        0x03,
        0x1d,
        0x33,
        0x26,
        0x4e,
        0x15,
        0xd3,
        0x32,
        0x68,
        0xf2,
        0x4e,
        0xc2,
        0x60,
        0x74,
        0x3e,
        0xdc,
        0xe1,
        0xc6,
        0xc7,
        0xdd,
        0xee,
        0x72,
        0x5a,
        0x93,
        0x6b,
        0xa8,
        0x14,
        0x91,
        0x5c,
        0x67,
        0x62,
        0xd2
      ]);

      final wrappedKey128 = AesKeyWrapper.wrap(key192, keyData128);
      var unwrappedKey128 = AesKeyWrapper.unwrap(key192, wrappedKey128);
      expect(wrappedKey128, equals(wrappedKey128192));
      expect(unwrappedKey128, equals(keyData128));

      final wrappedKey192 = AesKeyWrapper.wrap(key192, keyData192);
      var unwrappedKey192 = AesKeyWrapper.unwrap(key192, wrappedKey192);
      expect(wrappedKey192, equals(wrappedKey192192));
      expect(unwrappedKey192, equals(keyData192));

      final key = Helper.secureRandom().nextBytes(24);
      final keyData = Helper.secureRandom().nextBytes(32);
      final wrappedKey = AesKeyWrapper.wrap(key, keyData);
      var unwrappedKey = AesKeyWrapper.unwrap(key, wrappedKey);
      expect(unwrappedKey, equals(keyData));
    });

    test('256-bit test', () {
      final wrappedKey128256 = Uint8List.fromList([
        0x64,
        0xe8,
        0xc3,
        0xf9,
        0xce,
        0x0f,
        0x5b,
        0xa2,
        0x63,
        0xe9,
        0x77,
        0x79,
        0x05,
        0x81,
        0x8a,
        0x2a,
        0x93,
        0xc8,
        0x19,
        0x1e,
        0x7d,
        0x6e,
        0x8a,
        0xe7,
      ]);
      final wrappedKey192256 = Uint8List.fromList([
        0xa8,
        0xf9,
        0xbc,
        0x16,
        0x12,
        0xc6,
        0x8b,
        0x3f,
        0xf6,
        0xe6,
        0xf4,
        0xfb,
        0xe3,
        0x0e,
        0x71,
        0xe4,
        0x76,
        0x9c,
        0x8b,
        0x80,
        0xa3,
        0x2c,
        0xb8,
        0x95,
        0x8c,
        0xd5,
        0xd1,
        0x7d,
        0x6b,
        0x25,
        0x4d,
        0xa1,
      ]);
      final wrappedKey256256 = Uint8List.fromList([
        0x28,
        0xc9,
        0xf4,
        0x04,
        0xc4,
        0xb8,
        0x10,
        0xf4,
        0xcb,
        0xcc,
        0xb3,
        0x5c,
        0xfb,
        0x87,
        0xf8,
        0x26,
        0x3f,
        0x57,
        0x86,
        0xe2,
        0xd8,
        0x0e,
        0xd3,
        0x26,
        0xcb,
        0xc7,
        0xf0,
        0xe7,
        0x1a,
        0x99,
        0xf4,
        0x3b,
        0xfb,
        0x98,
        0x8b,
        0x9b,
        0x7a,
        0x02,
        0xdd,
        0x21,
      ]);

      final wrappedKey128 = AesKeyWrapper.wrap(key256, keyData128);
      var unwrappedKey128 = AesKeyWrapper.unwrap(key256, wrappedKey128);
      expect(wrappedKey128, equals(wrappedKey128256));
      expect(unwrappedKey128, equals(keyData128));

      final wrappedKey192 = AesKeyWrapper.wrap(key256, keyData192);
      var unwrappedKey192 = AesKeyWrapper.unwrap(key256, wrappedKey192);
      expect(wrappedKey192, equals(wrappedKey192256));
      expect(unwrappedKey192, equals(keyData192));

      final wrappedKey256 = AesKeyWrapper.wrap(key256, keyData256);
      var unwrappedKey256 = AesKeyWrapper.unwrap(key256, wrappedKey256);
      expect(wrappedKey256, equals(wrappedKey256256));
      expect(unwrappedKey256, equals(keyData256));

      final key = Helper.secureRandom().nextBytes(32);
      final keyData = Helper.secureRandom().nextBytes(32);
      final wrappedKey = AesKeyWrapper.wrap(key, keyData);
      var unwrappedKey = AesKeyWrapper.unwrap(key, wrappedKey);
      expect(unwrappedKey, equals(keyData));
    });
  });
}
