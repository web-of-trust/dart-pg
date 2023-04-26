// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/math/byte_ext.dart';
import '../enum/packet_tag.dart';

/// Generic Packet Data Reader function
class PacketReader {
  final PacketTag tag;

  final Uint8List data;

  final int start;

  final int end;

  PacketReader(this.tag, this.data, this.start, this.end);

  factory PacketReader.read(final Uint8List bytes, [final int start = 0]) {
    if (bytes.length <= start ||
        bytes.sublist(start).length < 2 ||
        (bytes[start] & 0x80) == 0) {
      throw StateError(
        'Error during parsing. This data probably does not conform to a valid OpenPGP format.',
      );
    }

    var pos = start;

    final headerByte = bytes[pos++];
    final oldFormat = ((headerByte & 0x40) != 0) ? false : true;
    final tagByte = oldFormat ? (headerByte & 0x3f) >> 2 : headerByte & 0x3f;
    final tag = PacketTag.values.firstWhere((tag) => tag.value == tagByte);

    var packetLength = bytes.length - start;
    if (oldFormat) {
      final lengthType = headerByte & 0x03;
      switch (lengthType) {
        case 0:
          packetLength = bytes[pos++];
          break;
        case 1:
          packetLength = (bytes[pos++] << 8) | bytes[pos++];
          break;
        case 2:
          packetLength = bytes.sublist(pos, pos + 4).toInt32();
          pos += 4;
          break;
      }
    } else {
      if (bytes[pos] < 192) {
        packetLength = bytes[pos++];
      } else if (bytes[pos] > 191 && bytes[pos] < 224) {
        packetLength = ((bytes[pos++] - 192) << 8) + (bytes[pos++]) + 192;
      } else if (bytes[pos] > 223 && bytes[pos] < 255) {
        var partialPos = pos + 1 << (bytes[pos++] & 0x1f);
        while (true) {
          if (bytes[pos] < 192) {
            final partialLen = bytes[partialPos++];
            partialPos += partialLen;
            break;
          } else if (bytes[partialPos] > 191 && bytes[partialPos] < 224) {
            final partialLen = ((bytes[partialPos++] - 192) << 8) +
                (bytes[partialPos++]) +
                192;
            partialPos += partialLen;
            break;
          } else if (bytes[partialPos] > 223 && bytes[partialPos] < 255) {
            final partialLen = 1 << (bytes[partialPos++] & 0x1f);
            partialPos += partialLen;
            break;
          } else {
            partialPos++;
            final partialLen =
                bytes.sublist(partialPos, partialPos + 4).toInt32();
            partialPos += 4;
            partialPos += partialLen;
          }
        }
        packetLength = partialPos - pos;
      } else {
        pos++;
        packetLength = bytes.sublist(pos, pos + 4).toInt32();
        pos += 4;
      }
    }

    return PacketReader(
      tag,
      bytes.sublist(pos, pos + packetLength),
      start,
      pos + packetLength,
    );
  }
}
