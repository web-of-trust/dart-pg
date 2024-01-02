// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../crypto/math/byte_ext.dart';

export 'aes_key_wrap.dart';
export 'camellia_key_wrap.dart';

/// An implementation of the key wrapper based on RFC 3394.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class KeyWrap {
  static final _iv = Uint8List.fromList([
    0xa6, 0xa6, 0xa6, 0xa6, // 0 - 3
    0xa6, 0xa6, 0xa6, 0xa6
  ]);

  final BlockCipher cipher;

  final int keySize;

  KeyWrap(this.cipher, this.keySize);

  Future<Uint8List> wrap(
    final Uint8List kek,
    final Uint8List key,
  ) async {
    if (kek.lengthInBytes != keySize) {
      throw ArgumentError('Key encryption key size must be $keySize bytes.');
    }
    if (key.lengthInBytes < 16) {
      throw ArgumentError('Key length must be at least 16 octets.');
    }
    if (key.lengthInBytes % 8 != 0) {
      throw ArgumentError('Key length must be a multiple of 64 bits.');
    }

    cipher.init(true, KeyParameter(kek));
    final a = Uint8List.fromList(_iv);
    final r = Uint8List.fromList(key);
    final n = key.lengthInBytes ~/ 8;
    for (var j = 0; j <= 5; j++) {
      for (var i = 1; i <= n; i++) {
        final buffer = Uint8List.fromList([
          ...a,
          ...r.sublist((i - 1) * 8, i * 8),
        ]);
        cipher.processBlock(buffer, 0, buffer, 0);

        a.setAll(0, buffer.sublist(0, 8));
        a[7] ^= (n * j + i) & 0xff;
        r.setAll((i - 1) * 8, buffer.sublist(8, 16));
      }
    }
    return Uint8List.fromList([...a, ...r]);
  }

  Future<Uint8List> unwrap(
    final Uint8List kek,
    final Uint8List wrappedKey,
  ) async {
    if (kek.lengthInBytes != keySize) {
      throw ArgumentError('Key encryption key size must be $keySize bytes.');
    }
    if (wrappedKey.lengthInBytes < 16) {
      throw ArgumentError('Wrapped key length must be at least 16 octets.');
    }
    if (wrappedKey.lengthInBytes % 8 != 0) {
      throw ArgumentError('Wrapped key length must be a multiple of 64 bits.');
    }

    cipher.init(false, KeyParameter(kek));
    final a = wrappedKey.sublist(0, 8);
    final r = wrappedKey.sublist(8);
    final n = (wrappedKey.lengthInBytes ~/ 8) - 1;
    for (var j = 5; j >= 0; j--) {
      for (var i = n; i >= 1; i--) {
        a[7] ^= (n * j + i) & 0xff;
        final buffer = Uint8List.fromList([
          ...a,
          ...r.sublist((i - 1) * 8, i * 8),
        ]);
        cipher.processBlock(buffer, 0, buffer, 0);

        a.setAll(0, buffer.sublist(0, 8));
        r.setAll((i - 1) * 8, buffer.sublist(8, 16));
      }
    }

    if (!_iv.equals(a)) {
      throw StateError('Integrity check failed.');
    }

    return r;
  }
}
