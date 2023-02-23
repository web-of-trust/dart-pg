// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../crypto/symmetric/rfc3394_wrap.dart';

/// Implementation of RFC 3394 AES Key Wrap & Key Unwrap funcions
class AesKeyWrapper {
  static Uint8List wrap(final Uint8List key, final Uint8List data) {
    final engine = Rfc3394WrapEngine(BlockCipher('AES/CFB-${key.length * 8}'));
    engine.init(true, KeyParameter(key));
    return engine.wrap(data, 0, data.lengthInBytes);
  }

  static Uint8List unwrap(final Uint8List key, final Uint8List data) {
    final engine = Rfc3394WrapEngine(BlockCipher('AES/CFB-${key.length * 8}'));
    engine.init(false, KeyParameter(key));
    return engine.unwrap(data, 0, data.lengthInBytes);
  }
}
