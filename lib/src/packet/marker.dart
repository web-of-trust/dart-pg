/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';

import 'base_packet.dart';

/// Implementation of the Marker (MARKER) Packet - Type 10
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class MarkerPacket extends BasePacket {
  static const marker = 'PGP';

  MarkerPacket() : super(PacketType.marker);

  @override
  get data => utf8.encoder.convert(marker);
}
