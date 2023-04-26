// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enum/packet_tag.dart';
import '../crypto/math/int_ext.dart';

abstract class ContainedPacket {
  final PacketTag tag;

  ContainedPacket(this.tag);

  /// Serializes packet data to bytes
  Uint8List toByteData();

  /// Serializes packet to bytes
  Uint8List encode() {
    final bodyData = toByteData();
    final bodyLen = bodyData.length;

    final List<int> headerData;
    final hdr = 0x80 | 0x40 | tag.value;
    if (bodyLen < 192) {
      headerData = [hdr, bodyLen];
    } else if (bodyLen <= 8383) {
      headerData = [
        hdr,
        (((bodyLen - 192) >> 8) & 0xff) + 192,
        bodyLen - 192,
      ];
    } else {
      headerData = [hdr, 0xff, ...bodyLen.pack32()];
    }
    return Uint8List.fromList([...headerData, ...bodyData]);
  }
}
