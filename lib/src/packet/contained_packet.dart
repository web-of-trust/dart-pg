// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enum/packet_tag.dart';
import '../crypto/math/int_ext.dart';

abstract class ContainedPacket {
  final PacketTag tag;

  ContainedPacket(this.tag);

  Uint8List toByteData();

  Uint8List encode({final bool oldFormat = false, final bool partial = false}) {
    final bodyData = toByteData();
    final bodyLen = bodyData.length;

    final List<int> headerData;
    if (oldFormat) {
      final hdr = 0x80 | (tag.value << 2);
      if (partial) {
        headerData = [hdr | 0x03];
      } else {
        if (bodyLen <= 0xff) {
          headerData = [hdr, bodyLen];
        } else if (bodyLen <= 0xffff) {
          headerData = [hdr | 0x01, ...bodyLen.pack16()];
        } else {
          headerData = [hdr | 0x02, ...bodyLen.pack32()];
        }
      }
    } else {
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
    }
    return Uint8List.fromList([...headerData, ...bodyData]);
  }
}
