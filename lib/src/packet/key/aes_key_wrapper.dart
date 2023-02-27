// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../helpers.dart';

/// Implementation of RFC 3394 AES Key Wrap & Key Unwrap funcions
class AesKeyWrapper {
  static final _iv = Uint8List.fromList([
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
    0xa6,
  ]);

  static Uint8List wrap(final Uint8List key, final Uint8List data) {
    if (data.lengthInBytes < 16) {
      throw StateError('Data to be wrapped should be at least 128 bits');
    }

    if (data.lengthInBytes % 8 != 0) {
      throw StateError('Data to be wrapped must be a multiple of 8 bytes');
    }

    final engine = BlockCipher('AES/ECB');
    engine.init(true, KeyParameter(key));

    final a = Uint8List.fromList(_iv);
    final r = data;
    final n = data.lengthInBytes ~/ 8;
    for (var j = 0; j <= 5; j++) {
      for (var i = 1; i <= n; i++) {
        final buffer = Uint8List.fromList([
          ...a,
          ...r.sublist((i - 1) * 8, i * 8),
        ]);
        engine.processBlock(buffer, 0, buffer, 0);

        a.setAll(0, buffer.sublist(0, 8));
        a[7] ^= (n * j + i) & 0xff;
        r.setAll((i - 1) * 8, buffer.sublist(8, 16));
      }
    }
    return Uint8List.fromList([...a, ...r]);
  }

  static Uint8List unwrap(final Uint8List key, final Uint8List data) {
    if (data.lengthInBytes < 16) {
      throw StateError('Data to be unwrapped should be at least 128 bits');
    }

    if (data.lengthInBytes % 8 != 0) {
      throw StateError('Data to be unwrapped must be a multiple of 8 bytes');
    }

    final engine = BlockCipher('AES/ECB');
    engine.init(false, KeyParameter(key));

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
        engine.processBlock(buffer, 0, buffer, 0);

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
