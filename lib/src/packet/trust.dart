/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'base.dart';

/// Implementation of the Trust (TRUST) Packet - Type 12
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class TrustPacket extends BasePacket {
  final Uint8List levelAndTrustAmount;

  TrustPacket(this.levelAndTrustAmount) : super(PacketType.trust);

  factory TrustPacket.fromTrustCode(final int trustCode) => TrustPacket(
        Uint8List.fromList([trustCode & 0xff]),
      );

  factory TrustPacket.fromBytes(final Uint8List bytes) => TrustPacket.fromTrustCode(
        bytes[0],
      );

  @override
  Uint8List get data => levelAndTrustAmount;
}
