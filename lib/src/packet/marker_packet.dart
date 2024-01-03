// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../enum/packet_tag.dart';
import 'contained_packet.dart';

/// Implementation of the strange "Marker packet" (Tag 10)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class MarkerPacket extends ContainedPacket {
  static const marker = 'PGP';

  MarkerPacket() : super(PacketTag.marker);

  @override
  Uint8List toByteData() {
    return utf8.encoder.convert(marker);
  }
}
