// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';

/// Generic Packet Data Parser function
class PacketData {
  final PacketTag tag;

  final Uint8List data;

  final int offset;

  PacketData(this.tag, this.data, this.offset);

  factory PacketData.readPacketData(final Uint8List bytes, [final int offset = 0]) {
    if (bytes.length <= offset || bytes.sublist(offset).length < 2 || (bytes[offset] & 0x80) == 0) {
      throw Exception('Error during parsing. This message / key probably does not conform to a valid OpenPGP format.');
    }

    var pos = offset;

    final headerByte = bytes[pos];
    final oldFormat = ((headerByte & 0x40) != 0) ? false : true;
    final tagByte = oldFormat ? (headerByte & 0x3F) >> 2 : headerByte & 0x3F;
    final tag = PacketTag.values.firstWhere((tag) => tag.value == tagByte);

    final packetLengthType = oldFormat ? bytes[pos] & 0x03 : 0;
    pos++;

    final List<int> bodyData = [];
    var packetLength = bytes.length - offset;
    var realRacketLength = -1;
    if (oldFormat) {
      switch (packetLengthType) {
        case 0:
          packetLength = bytes[pos++];
          break;
        case 1:
          packetLength = (bytes[pos++] << 8) | bytes[pos++];
          break;
        case 2:
          packetLength = bytes.sublist(pos, pos + 4).toIn32();
          pos += 4;
          break;
      }
    } else {
      if (bytes[pos] < 192) {
        packetLength = bytes[pos++];
      } else if (bytes[pos] >= 192 && bytes[pos] < 224) {
        packetLength = ((bytes[pos++] - 192) << 8) + (bytes[pos++]) + 192;
      } else if (bytes[pos] > 223 && bytes[pos] < 255) {
        packetLength = 1 << (bytes[pos++] & 0x1F);
        var partialPos = pos + packetLength;
        while (true) {
          if (bytes[pos] < 192) {
            final partialLen = bytes[partialPos++];
            bodyData.addAll(bytes.sublist(partialPos, partialPos + partialLen));
            packetLength += partialLen;
            partialPos += partialLen;
            break;
          } else if (bytes[partialPos] >= 192 && bytes[partialPos] < 224) {
            final partialLen = ((bytes[partialPos++] - 192) << 8) + (bytes[partialPos++]) + 192;
            bodyData.addAll(bytes.sublist(partialPos, partialPos + partialLen));
            packetLength += partialLen;
            partialPos += partialLen;
            break;
          } else if (bytes[partialPos] > 223 && bytes[partialPos] < 255) {
            final partialLen = 1 << (bytes[partialPos++] & 0x1F);
            bodyData.addAll(bytes.sublist(partialPos, partialPos + partialLen));
            packetLength += partialLen;
            partialPos += partialLen;
            break;
          } else {
            partialPos++;

            final partialLen = bytes.sublist(partialPos, partialPos + 4).toIn32();
            partialPos += 4;

            bodyData.addAll(bytes.sublist(partialPos, partialPos + partialLen));
            packetLength += partialLen;
            partialPos += partialLen;
          }
        }
        realRacketLength = partialPos - pos;
      } else {
        pos++;
        packetLength = bytes.sublist(pos, pos + 4).toIn32();
        pos += 4;
      }
    }

    if (realRacketLength == -1) {
      realRacketLength = packetLength;
    }

    if (bodyData.isEmpty) {
      bodyData.addAll(bytes.sublist(pos, pos + realRacketLength));
    }

    return PacketData(tag, Uint8List.fromList(bodyData), pos + realRacketLength);
  }
}
