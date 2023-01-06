// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../helpers.dart';

/// Generic Sub Packet Data Parser function
class SubpacketRange {
  final int length;

  final int offset;

  SubpacketRange(this.length, this.offset);

  factory SubpacketRange.readSubpacketRange(final Uint8List bytes) {
    final type = bytes[0];
    if (type < 192) {
      return SubpacketRange(type, 1);
    } else if (type < 255) {
      return SubpacketRange(((type - 192) << 8) + (bytes[1]) + 192, 2);
    } else if (type == 255) {
      return SubpacketRange(bytes.sublist(1).toInt32(), 5);
    }
    return SubpacketRange(0, 0);
  }
}
