// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../helpers.dart';

/// Generic Sub Packet Data Parser function
class SubpacketData {
  final Uint8List data;

  final int start;

  final int end;

  final bool isLongLength;

  SubpacketData(this.data, this.start, this.end, [this.isLongLength = false]);

  factory SubpacketData.readSubpacketData(final Uint8List bytes, [final int start = 0]) {
    var pos = start;
    final type = bytes[pos++];
    if (type < 192) {
      return SubpacketData(bytes.sublist(pos, pos + type), start, pos + type);
    } else if (type < 255) {
      final length = ((type - 192) << 8) + (bytes[pos++]) + 192;
      return SubpacketData(bytes.sublist(pos, pos + length), start, pos + length);
    } else if (type == 255) {
      final length = bytes.sublist(pos, pos + 4).toUint32();
      pos += 4;
      return SubpacketData(bytes.sublist(pos, pos + length), start, pos + length, true);
    }
    return SubpacketData(Uint8List(0), start, start);
  }
}
