/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/extensions.dart';
import '../enum/packet_type.dart';

/// Packet Data Reader
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class PacketReader {
  final PacketType type;

  final Uint8List data;

  final int offset;

  PacketReader(this.type, this.data, this.offset);

  factory PacketReader.read(
    final Uint8List bytes, [
    final int offset = 0,
  ]) {
    if (bytes.length <= offset || bytes.sublist(offset).length < 2 || (bytes[offset] & 0x80) == 0) {
      throw ArgumentError(
        'Error during parsing.'
        'This data probably does not conform to a valid OpenPGP format.',
      );
    }

    var pos = offset;

    final headerByte = bytes[pos++];
    final oldFormat = ((headerByte & 0x40) != 0) ? false : true;
    final tagByte = oldFormat ? (headerByte & 0x3f) >> 2 : headerByte & 0x3f;
    final type = PacketType.values.firstWhere((tag) => tag.value == tagByte);

    final Uint8List packetData;
    var packetLen = bytes.length - pos;
    if (oldFormat) {
      final lengthType = headerByte & 0x03;
      switch (lengthType) {
        case 0:
          packetLen = bytes[pos++];
          break;
        case 1:
          packetLen = bytes.sublist(pos, pos + 2).unpack16();
          pos += 2;
          break;
        case 2:
          packetLen = bytes.sublist(pos, pos + 4).unpack32();
          pos += 4;
          break;
      }
      packetData = bytes.sublist(pos, pos + packetLen);
    } else {
      final length = bytes[pos++];
      if (length < 192) {
        packetLen = length;
        packetData = bytes.sublist(pos, pos + packetLen);
      } else if (length < 224) {
        packetLen = ((length - 192) << 8) + (bytes[pos++]) + 192;
        packetData = bytes.sublist(pos, pos + packetLen);
      } else if (length < 255) {
        var partialLen = 1 << (length & 0x1f);
        final List<Uint8List> partialData = List.empty(growable: true);
        partialData.add(bytes.sublist(pos, pos + partialLen));
        var partialPos = pos + partialLen;
        while (true) {
          partialLen = bytes[partialPos++];
          if (partialLen < 192) {
            partialData.add(
              bytes.sublist(partialPos, partialPos + partialLen),
            );
            partialPos += partialLen;
            break;
          } else if (partialLen < 224) {
            partialLen = ((partialLen - 192) << 8) + (bytes[partialPos++]) + 192;
            partialData.add(
              bytes.sublist(partialPos, partialPos + partialLen),
            );
            partialPos += partialLen;
            break;
          } else if (partialLen < 255) {
            partialLen = 1 << (partialLen & 0x1f);
            partialData.add(
              bytes.sublist(partialPos, partialPos + partialLen),
            );
            partialPos += partialLen;
          } else {
            partialLen = bytes
                .sublist(
                  partialPos,
                  partialPos + 4,
                )
                .unpack32();
            partialPos += 4;
            partialData.add(
              bytes.sublist(partialPos, partialPos + partialLen),
            );
            partialPos += partialLen;
            break;
          }
        }
        packetData = Uint8List.fromList([
          ...partialData.expand((element) => element),
        ]);
        packetLen = partialPos - pos;
      } else {
        packetLen = bytes.sublist(pos, pos + 4).unpack32();
        pos += 4;
        packetData = bytes.sublist(pos, pos + packetLen);
      }
    }

    return PacketReader(
      type,
      packetData,
      pos + packetLen,
    );
  }
}
