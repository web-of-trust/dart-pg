// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

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
    final KeyPacket keyPacket, {
    final SignaturePacket? signature,
    final DateTime? date,
  }) {
    if (revocationSignatures.isNotEmpty) {
      for (var revocation in revocationSignatures) {
        if (signature == null || revocation.issuerKeyID.keyID == signature.issuerKeyID.keyID) {
          if (revocation.verifyUserCertification(
            keyPacket,
            userID: userID,
            userAttribute: userAttribute,
            date: date,
          )) {
            return true;
          }
        }
      }
    }
    return false;
  }

  bool verify(
    final KeyPacket keyPacket, {
    final DateTime? date,
  }) {
    if (isRevoked(keyPacket, date: date)) {
      return false;
    }
    for (final signature in selfCertifications) {
      if (!signature.verifyUserCertification(
        keyPacket,
        userID: userID,
        userAttribute: userAttribute,
        date: date,
      )) {
        return false;
      }
    }
    return true;
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
