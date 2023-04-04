// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../crypto/math/byte_ext.dart';

export 'aes_key_wrap.dart';
export 'camellia_key_wrap.dart';

/// An implementation of the key wrapper based on RFC 3394.
abstract class KeyWrap {
  static final _iv = Uint8List.fromList([
    0xa6, 0xa6, 0xa6, 0xa6, // 0 - 3
    0xa6, 0xa6, 0xa6, 0xa6
  ]);

  final BlockCipher _cipher;

  KeyWrap(this._cipher);

  Future<Uint8List> wrap(
    final Uint8List key,
    final Uint8List data,
  ) async {
    if (data.lengthInBytes < 16) {
      throw StateError('Data to be wrapped should be at least 128 bits');
    }
    if (data.lengthInBytes % 8 != 0) {
      throw StateError('Data to be wrapped must be a multiple of 8 bytes');
    }

    _cipher.init(true, KeyParameter(key));
    final a = Uint8List.fromList(_iv);
    final r = Uint8List.fromList(data);
    final n = data.lengthInBytes ~/ 8;
    for (var j = 0; j <= 5; j++) {
      for (var i = 1; i <= n; i++) {
        final buffer = Uint8List.fromList([
          ...a,
          ...r.sublist((i - 1) * 8, i * 8),
        ]);
        _cipher.processBlock(buffer, 0, buffer, 0);

        a.setAll(0, buffer.sublist(0, 8));
        a[7] ^= (n * j + i) & 0xff;
        r.setAll((i - 1) * 8, buffer.sublist(8, 16));
      }
    }
    return Uint8List.fromList([...a, ...r]);
  }

  Future<Uint8List> unwrap(
    final Uint8List key,
    final Uint8List data,
  ) async {
    if (data.lengthInBytes < 16) {
      throw StateError('Data to be unwrapped should be at least 128 bits');
    }
    if (data.lengthInBytes % 8 != 0) {
      throw StateError('Data to be unwrapped must be a multiple of 8 bytes');
    }

    _cipher.init(false, KeyParameter(key));
    final a = data.sublist(0, 8);
    final r = data.sublist(8);
    final n = (data.lengthInBytes ~/ 8) - 1;
    for (var j = 5; j >= 0; j--) {
      for (var i = n; i >= 1; i--) {
        a[7] ^= (n * j + i) & 0xff;
        final buffer = Uint8List.fromList([
          ...a,
          ...r.sublist((i - 1) * 8, i * 8),
        ]);
        _cipher.processBlock(buffer, 0, buffer, 0);

        a.setAll(0, buffer.sublist(0, 8));
        r.setAll((i - 1) * 8, buffer.sublist(8, 16));
      }
    }

    if (!_iv.equals(a)) {
      throw StateError('Checksum failed');
    }

    return r;
  }
}
