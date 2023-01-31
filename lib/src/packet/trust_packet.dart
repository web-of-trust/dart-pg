// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

class TrustPacketPacket extends ContainedPacket {
  final Uint8List levelAndTrustAmount;

  TrustPacketPacket(
    this.levelAndTrustAmount, {
    super.tag = PacketTag.trust,
  });

  factory TrustPacketPacket.fromTrustCode(final int trustCode) =>
      TrustPacketPacket(Uint8List.fromList([trustCode & 0xff]));

  factory TrustPacketPacket.fromPacketData(final Uint8List bytes) => TrustPacketPacket.fromTrustCode(bytes[0]);

  @override
  Uint8List toPacketData() {
    return levelAndTrustAmount;
  }
}
