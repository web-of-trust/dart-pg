// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../byte_utils.dart';
import '../enums.dart';

abstract class ContainedPacket {
  final PacketTag tag;

  ContainedPacket({required this.tag});

  Uint8List toPacketData();

  Uint8List packetEncode({bool oldFormat = true, bool partial = false}) {
    final List<int> packetHeader = [];
    final packetBody = toPacketData();
    final bodyLen = packetBody.length;

    var hdr = 0x80;
    if (oldFormat) {
      hdr |= tag.value << 2;
      if (partial) {
        packetHeader.add(hdr | 0x03);
      } else {
        if (bodyLen <= 0xff) {
          packetHeader.addAll([hdr, bodyLen]);
        } else if (bodyLen <= 0xffff) {
          packetHeader.addAll([hdr | 0x01, ...ByteUtils.int16Bytes(bodyLen)]);
        } else {
          packetHeader.addAll([hdr | 0x02, ...ByteUtils.int32Bytes(bodyLen)]);
        }
      }
    } else {
      packetHeader.add(hdr | tag.value | 0x40);
      if (bodyLen < 192) {
        packetHeader.add(bodyLen);
      } else if (bodyLen <= 8383) {
        packetHeader.addAll([(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192]);
      } else {
        packetHeader.addAll([0xff, ...ByteUtils.int32Bytes(bodyLen)]);
      }
    }
    return Uint8List.fromList([...packetHeader, ...packetBody]);
  }
}
