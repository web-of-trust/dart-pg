/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/helpers.dart';
import '../packet/base_packet.dart';
import '../packet/packet_list.dart';
import '../type/key.dart';
import '../type/signature_packet.dart';
import '../type/user.dart';
import '../type/user_id_packet.dart';

/// OpenPGP user class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class User implements UserInterface {
  @override
  final KeyInterface mainKey;

  @override
  final UserIDPacketInterface userIDPacket;

  @override
  final List<SignaturePacketInterface> revocationSignatures;

  @override
  final List<SignaturePacketInterface> selfSignatures;

  @override
  final List<SignaturePacketInterface> otherSignatures;

  User(
    this.mainKey,
    this.userIDPacket, {
    this.revocationSignatures = const [],
    this.selfSignatures = const [],
    this.otherSignatures = const [],
  });

  @override
  get isPrimary {
    final signatures = selfSignatures.toList();
    signatures.sort(
      (a, b) => b.creationTime.compareTo(
        a.creationTime,
      ),
    );
    for (final signature in signatures) {
      if (signature.isPrimaryUserID) {
        return true;
      }
    }
    return false;
  }

  @override
  get packetList => PacketList([
        userIDPacket,
        ...revocationSignatures,
        ...selfSignatures,
        ...otherSignatures,
      ]);

  @override
  get userID => (userIDPacket is UserIDPacket) ? (userIDPacket as UserIDPacket).userID : "";

  @override
  isRevoked([final DateTime? time]) {
    for (final revocation in revocationSignatures) {
      if (revocation.verify(
        mainKey.keyPacket,
        Uint8List.fromList([
          ...mainKey.keyPacket.signBytes,
          ...userIDPacket.signBytes,
        ]),
        time,
      )) {
        return true;
      }
    }
    return false;
  }

  @override
  isCertified(
    final KeyInterface verifyKey, {
    final SignaturePacketInterface? certificate,
    final DateTime? time,
  }) {
    if (otherSignatures.isNotEmpty) {
      final keyID = certificate?.issuerKeyID;
      final keyPacket = verifyKey.publicKey.keyPacket;
      for (final signature in otherSignatures) {
        if (keyID == null || signature.issuerKeyID.equals(keyID)) {
          if (signature.verify(
            keyPacket,
            Uint8List.fromList([
              ...mainKey.keyPacket.signBytes,
              ...userIDPacket.signBytes,
            ]),
            time,
          )) {
            return true;
          }
        }
      }
    }
    return false;
  }

  @override
  verify([final DateTime? time]) {
    for (final signature in selfSignatures) {
      if (signature.verify(
        mainKey.keyPacket,
        Uint8List.fromList([
          ...mainKey.keyPacket.signBytes,
          ...userIDPacket.signBytes,
        ]),
        time,
      )) {
        return true;
      }
    }
    return false;
  }
}
