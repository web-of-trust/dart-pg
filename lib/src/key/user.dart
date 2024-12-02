/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/packet_list.dart';
import 'package:dart_pg/src/type/signature_packet.dart';
import 'package:dart_pg/src/type/user.dart';
import 'package:dart_pg/src/type/user_id_packet.dart';

/// OpenPGP user class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class User implements UserInterface {
  @override
  final KeyInterface mainKey;

  @override
  final UserIDPacketInterface userIDPacket;

  @override
  final List<SignaturePacketInterface> selfSignatures;

  @override
  final List<SignaturePacketInterface> otherSignatures;

  @override
  final List<SignaturePacketInterface> revocationSignatures;

  User(
    this.mainKey,
    this.userIDPacket, {
    this.selfSignatures = const [],
    this.otherSignatures = const [],
    this.revocationSignatures = const [],
  });

  @override
  bool get isPrimary {
    final signatures = selfSignatures.toList();
    signatures.sort(
      (a, b) => b.creationTime!.compareTo(
        a.creationTime!,
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
  PacketListInterface get packetList => PacketList([
        userIDPacket,
        ...revocationSignatures,
        ...selfSignatures,
        ...otherSignatures,
      ]);

  @override
  String get userID => (userIDPacket is UserIDPacket) ? (userIDPacket as UserIDPacket).userID : "";

  @override
  bool isRevoked([DateTime? time]) {
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
  bool verify([DateTime? time]) {
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
