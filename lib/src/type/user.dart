// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import '../packet/key_packet.dart';
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

  /// Checks if a given certificate of the user is revoked
  bool isRevoked(
    KeyPacket keyPacket, {
    SignaturePacket? signature,
    final DateTime? date,
  }) {
    if (revocationSignatures.isNotEmpty) {
      for (var revocation in revocationSignatures) {
        if (signature == null || revocation.issuerKeyID.keyID == signature.issuerKeyID.keyID) {
          return revocation.verify(
            keyPacket,
            keyData: keyPacket,
            userIdData: userID,
            userAttributeData: userAttribute,
            signatureType: SignatureType.certRevocation,
            date: date,
          );
        }
      }
    }
    return false;
  }

  PacketList toPacketList() {
    return PacketList([
      userID ?? userAttribute!,
      ...revocationSignatures,
      ...selfCertifications,
      ...otherCertifications,
    ]);
  }
}
