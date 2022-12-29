// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

/// Implementation of the strange "Marker packet" (Tag 10)
class MarkerPacket extends ContainedPacket {
  static const marker = 'PGP';

  MarkerPacket({
    super.tag = PacketTag.marker,
  });

  @override
  Uint8List toPacketData() {
    return utf8.encoder.convert(marker);
  }
}
