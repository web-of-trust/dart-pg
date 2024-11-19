/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/extensions.dart';

/// Sub Packet Data Reader
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class SubpacketReader {
  final int type;

  final Uint8List data;

  final int offset;

  final bool isLong;

  SubpacketReader(
    this.type,
    this.data,
    this.offset, [
    this.isLong = false,
  ]);

  factory SubpacketReader.read(
    final Uint8List bytes, [
    final int offset = 0,
  ]) {
    var pos = offset;
    final header = bytes[pos++];
    if (header < 192) {
      return SubpacketReader(
        bytes[pos],
        bytes.sublist(pos + 1, pos + header),
        pos + header,
      );
    } else if (header < 255) {
      final length = ((header - 192) << 8) + (bytes[pos++]) + 192;
      return SubpacketReader(
        bytes[pos],
        bytes.sublist(pos + 1, pos + length),
        pos + length,
      );
    } else if (header == 255) {
      final length = bytes.sublist(pos, pos + 4).unpack32();
      pos += 4;
      return SubpacketReader(
        bytes[pos],
        bytes.sublist(pos + 1, pos + length),
        pos + length,
        true,
      );
    }
    return SubpacketReader(0, Uint8List(0), offset);
  }
}
