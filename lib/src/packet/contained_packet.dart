// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';

abstract class ContainedPacket {
  final PacketTag tag;

  ContainedPacket({required this.tag});

  Uint8List toPacketData();

  Uint8List packetEncode({final bool oldFormat = true, final bool partial = false}) {
    final List<int> packetHeader = [];
    final packetBody = toPacketData();
    final bodyLen = packetBody.length;

    if (oldFormat) {
      final hdr = 0x80 | (tag.value << 2);
      if (partial) {
        packetHeader.add(hdr | 0x03);
      } else {
        if (bodyLen <= 0xff) {
          packetHeader.addAll([hdr, bodyLen]);
        } else if (bodyLen <= 0xffff) {
          packetHeader.addAll([hdr | 0x01, ...bodyLen.to16Bytes()]);
        } else {
          packetHeader.addAll([hdr | 0x02, ...bodyLen.to32Bytes()]);
        }
      }
    } else {
      packetHeader.add(0x80 | 0x40 | tag.value);
      if (bodyLen < 192) {
        packetHeader.add(bodyLen);
      } else if (bodyLen <= 8383) {
        packetHeader.addAll([(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192]);
      } else {
        packetHeader.addAll([0xff, ...bodyLen.to32Bytes()]);
      }
    }
    return Uint8List.fromList([...packetHeader, ...packetBody]);
  }
}
