// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/math/int_ext.dart';

class Crc24 {
  static const _init = 0xb704ce;
  static const _poly = 0x1864cfb;
  static const _mask = 0xffffff;

  static int calculate(final Uint8List bytes) {
    var crc = _init;
    for (final byte in bytes) {
      crc ^= byte << 16;
      for (var i = 0; i < 8; i++) {
        crc <<= 1;
        if ((crc & 0x1000000) != 0) {
          crc ^= _poly;
        }
      }
    }
    return crc & _mask;
  }

  static String base64Calculate(final Uint8List data) {
    return base64.encode(calculate(data).pack32().sublist(1));
  }
}
