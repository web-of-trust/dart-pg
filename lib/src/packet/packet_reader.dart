// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pinenacl/api.dart';

import '../crypto/math/byte_ext.dart';
import '../enum/packet_tag.dart';

/// Generic Packet Data Reader function
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PacketReader {
  final PacketTag tag;

  final Uint8List data;

  final int offset;

  PacketReader(this.tag, this.data, this.offset);

  factory PacketReader.read(final Uint8List bytes, [final int offset = 0]) {
    if (bytes.length <= offset ||
        bytes.sublist(offset).length < 2 ||
        (bytes[offset] & 0x80) == 0) {
      throw StateError(
        'Error during parsing. This data probably does not conform to a valid OpenPGP format.',
      );
    }

    var pos = offset;

    final headerByte = bytes[pos++];
    final oldFormat = ((headerByte & 0x40) != 0) ? false : true;
    final tagByte = oldFormat ? (headerByte & 0x3f) >> 2 : headerByte & 0x3f;
    final tag = PacketTag.values.firstWhere((tag) => tag.value == tagByte);

    final Uint8List packetData;
    var packetLength = bytes.length - pos;
    if (oldFormat) {
      final lengthType = headerByte & 0x03;
      switch (lengthType) {
        case 0:
          packetLength = bytes[pos++];
          break;
        case 1:
          packetLength = bytes.sublist(pos, pos + 2).toIn16();
          pos += 2;
          break;
        case 2:
          packetLength = bytes.sublist(pos, pos + 4).toInt32();
          pos += 4;
          break;
      }
      packetData = bytes.sublist(pos, pos + packetLength);
    } else {
      final length = bytes[pos++];
      if (length < 192) {
        packetLength = length;
        packetData = bytes.sublist(pos, pos + packetLength);
      } else if (length < 224) {
        packetLength = ((length - 192) << 8) + (bytes[pos++]) + 192;
        packetData = bytes.sublist(pos, pos + packetLength);
      } else if (length < 255) {
        var partialLength = 1 << (length & 0x1f);
        final List<Uint8List> partialData = List.empty(growable: true);
        partialData.add(bytes.sublist(pos, pos + partialLength));
        var partialPos = pos + partialLength;
        while (true) {
          partialLength = bytes[partialPos++];
          if (partialLength < 192) {
            partialData
                .add(bytes.sublist(partialPos, partialPos + partialLength));
            partialPos += partialLength;
            break;
          } else if (partialLength < 224) {
            partialLength =
                ((partialLength - 192) << 8) + (bytes[partialPos++]) + 192;
            partialData
                .add(bytes.sublist(partialPos, partialPos + partialLength));
            partialPos += partialLength;
            break;
          } else if (partialLength < 255) {
            partialLength = 1 << (partialLength & 0x1f);
            partialData
                .add(bytes.sublist(partialPos, partialPos + partialLength));
            partialPos += partialLength;
          } else {
            partialLength = bytes
                .sublist(
                  partialPos,
                  partialPos + 4,
                )
                .toInt32();
            partialPos += 4;
            partialData
                .add(bytes.sublist(partialPos, partialPos + partialLength));
            partialPos += partialLength;
            break;
          }
        }
        packetData = Uint8List.fromList([
          ...partialData.expand((element) => element),
        ]);
        packetLength = partialPos - pos;
      } else {
        packetLength = bytes.sublist(pos, pos + 4).toInt32();
        pos += 4;
        packetData = bytes.sublist(pos, pos + packetLength);
      }
    }

    return PacketReader(
      tag,
      packetData,
      pos + packetLength,
    );
  }
}
