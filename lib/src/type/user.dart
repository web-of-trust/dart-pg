// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'key.dart';

/// Class that represents an user ID and the relevant signatures.
class User {
  final Key? mainKey;

  final UserIDPacket? userID;

  final UserAttributePacket? userAttribute;

  final List<SignaturePacket> selfCertifications;

  final List<SignaturePacket> otherCertifications;

  final List<SignaturePacket> revocationSignatures;

  User({
    this.mainKey,
    this.userID,
    this.userAttribute,
    this.selfCertifications = const [],
    this.otherCertifications = const [],
    this.revocationSignatures = const [],
  });

  /// Checks if a given certificate of the user is revoked
  bool isRevoked({
    final SignaturePacket? signature,
    final DateTime? date,
  }) {
    if (mainKey != null && revocationSignatures.isNotEmpty) {
      for (var revocation in revocationSignatures) {
        if (signature == null || revocation.issuerKeyID.keyID == signature.issuerKeyID.keyID) {
          if (revocation.verifyUserCertification(
            mainKey!.keyPacket,
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

  bool verify({
    final DateTime? date,
  }) {
    if (isRevoked(date: date)) {
      return false;
    }
    if (mainKey != null) {
      for (final signature in selfCertifications) {
        if (!signature.verifyUserCertification(
          mainKey!.keyPacket,
          userID: userID,
          userAttribute: userAttribute,
          date: date,
        )) {
          return false;
        }
      }
    }
    return true;
  }

  /// Generate third-party certifications over this user and its primary key
  /// return new user with new certifications.
  User certify(
    List<PrivateKey> signingKeys, {
    final DateTime? date,
  }) {
    if (signingKeys.isNotEmpty) {
      return User(
        mainKey: mainKey,
        userID: userID,
        userAttribute: userAttribute,
        selfCertifications: selfCertifications,
        otherCertifications: signingKeys
            .map((key) => SignaturePacket.createCertifySignature(
                  key.getSigningKeyPacket(date: date),
                  userID: userID,
                  userAttribute: userAttribute,
                  date: date,
                ))
            .toList(growable: false),
        revocationSignatures: revocationSignatures,
      );
    }
    return this;
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
