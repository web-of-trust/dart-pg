/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../enum/packet_type.dart';
import 'base.dart';

/// Implementation of the strange "Marker packet" (Tag 10)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class MarkerPacket extends BasePacket {
  static const marker = 'PGP';

  MarkerPacket() : super(PacketType.marker);

  @override
  Uint8List get data => utf8.encoder.convert(marker);
}
