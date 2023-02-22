// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

/// Implementation of RFC 3394 AES Key Wrap & Key Unwrap funcions
class KeyWrapper {
  final BlockCipher cipherEngine;

  KeyWrapper(this.cipherEngine);

  wrap(final Uint8List key, final Uint8List data) {}

  unwrap(final Uint8List key, final Uint8List data) {}
}
