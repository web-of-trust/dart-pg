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
  Future<bool> isRevoked({
    final SignaturePacket? signature,
    final DateTime? date,
  }) async {
    if (mainKey != null && revocationSignatures.isNotEmpty) {
      for (var revocation in revocationSignatures) {
        if (signature == null ||
            revocation.issuerKeyID.id == signature.issuerKeyID.id) {
          if (await revocation.verifyUserCertification(
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

  Future<bool> verify({
    final DateTime? date,
  }) async {
    if (await isRevoked(date: date)) {
      return false;
    }
    if (mainKey != null) {
      for (final signature in selfCertifications) {
        if (!await signature.verifyUserCertification(
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
  Future<User> certify(
    List<PrivateKey> signingKeys, {
    final DateTime? date,
  }) async {
    if (signingKeys.isNotEmpty) {
      return User(
        mainKey: mainKey,
        userID: userID,
        userAttribute: userAttribute,
        selfCertifications: selfCertifications,
        otherCertifications: await Future.wait(
          signingKeys.map(
            (key) async => SignaturePacket.createCertifySignature(
              await key.getSigningKeyPacket(date: date),
              userID: userID,
              userAttribute: userAttribute,
              date: date,
            ),
          ),
        ),
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
