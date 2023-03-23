// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enum/packet_tag.dart';
import 'contained_packet.dart';

/// Implementation of the Trust Packet (Tag 12)
///
/// See https://tools.ietf.org/html/rfc4880#section-5.10
/// The Trust packet is used only within keyrings and is not normally exported.
/// Trust packets contain data that record the user's specificationsof which key holders are trustworthy introducers,
/// along with other information that implementing software uses for trust information.
/// The format of Trust packets is defined by a given implementation.
class TrustPacket extends ContainedPacket {
  final Uint8List levelAndTrustAmount;

  TrustPacket(this.levelAndTrustAmount) : super(PacketTag.trust);

  factory TrustPacket.fromTrustCode(final int trustCode) => TrustPacket(
        Uint8List.fromList([trustCode & 0xff]),
      );

  factory TrustPacket.fromByteData(final Uint8List bytes) =>
      TrustPacket.fromTrustCode(
        bytes[0],
      );

  @override
  Uint8List toByteData() {
    return levelAndTrustAmount;
  }
}
