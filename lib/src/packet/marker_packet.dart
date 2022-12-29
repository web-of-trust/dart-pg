// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

class MarkerPacket extends ContainedPacket {
  static const tag = PacketTag.marker;

  static const marker = 'PGP';

  @override
  Uint8List toPacketData() {
    return utf8.encoder.convert(marker);
  }
}
