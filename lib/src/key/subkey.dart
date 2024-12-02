/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/key/base.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/signature/key_flags.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/packet_list.dart';
import 'package:dart_pg/src/type/signature_packet.dart';
import 'package:dart_pg/src/type/subkey.dart';
import 'package:dart_pg/src/type/subkey_packet.dart';

/// OpenPGP subkey class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Subkey implements SubkeyInterface {
  @override
  final KeyInterface mainKey;

  @override
  final SubkeyPacketInterface keyPacket;

  @override
  final List<SignaturePacketInterface> revocationSignatures;

  @override
  final List<SignaturePacketInterface> bindingSignatures;

  Subkey(
    this.mainKey,
    this.keyPacket, {
    this.revocationSignatures = const [],
    this.bindingSignatures = const [],
  });

  @override
  DateTime get creationTime => keyPacket.creationTime;

  @override
  DateTime? get expirationTime => Base.keyExpiration(bindingSignatures);

  @override
  Uint8List get fingerprint => keyPacket.fingerprint;

  @override
  KeyAlgorithm get keyAlgorithm => keyPacket.keyAlgorithm;

  @override
  Uint8List get keyID => keyPacket.keyID;

  @override
  int get keyStrength => keyPacket.keyStrength;

  @override
  bool get isEncryptionKey {
    if (keyPacket.isEncryptionKey) {
      for (final signature in bindingSignatures) {
        final keyFlags = signature.getSubpacket<KeyFlags>();
        if (keyFlags != null && !(keyFlags.isEncryptStorage || keyFlags.isEncryptCommunication)) {
          return false;
        }
      }
    }
    return keyPacket.isEncryptionKey;
  }

  @override
  bool get isSigningKey {
    if (keyPacket.isSigningKey) {
      for (final signature in bindingSignatures) {
        final keyFlags = signature.getSubpacket<KeyFlags>();
        if (keyFlags != null && !(keyFlags.isSignData)) {
          return false;
        }
      }
    }
    return keyPacket.isSigningKey;
  }

  @override
  PacketListInterface get packetList => PacketList([
        keyPacket,
        ...revocationSignatures,
        ...bindingSignatures,
      ]);

  @override
  int get version => keyPacket.keyVersion;

  @override
  bool isRevoked([
    final DateTime? time,
  ]) {
    for (final revocation in revocationSignatures) {
      if (revocation.verify(
        mainKey.keyPacket,
        Uint8List.fromList([
          ...mainKey.keyPacket.signBytes,
          ...keyPacket.signBytes,
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
    for (final signature in bindingSignatures) {
      if (signature.verify(
        mainKey.keyPacket,
        Uint8List.fromList([
          ...mainKey.keyPacket.signBytes,
          ...keyPacket.signBytes,
        ]),
        time,
      )) {
        return true;
      }
    }
    return false;
  }
}
