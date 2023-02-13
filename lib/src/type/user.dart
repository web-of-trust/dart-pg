// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';

/// Class that represents an user ID and the relevant signatures.
class User {
  final UserIDPacket? userID;

  final UserAttributePacket? userAttribute;

  final List<SignaturePacket> selfCertifications = [];

  final List<SignaturePacket> otherCertifications = [];

  final List<SignaturePacket> revocationSignatures = [];

  User({
    this.userID,
    this.userAttribute,
  });

  PacketList toPacketList() {
    return PacketList([
      userID ?? userAttribute!,
      ...revocationSignatures,
      ...selfCertifications,
      ...otherCertifications,
    ]);
  }
}
