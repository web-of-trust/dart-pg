/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../packet/packet_list.dart';
import '../packet/signature/key_flags.dart';
import '../type/key.dart';
import '../type/signature_packet.dart';
import '../type/subkey_packet.dart';
import 'base_key.dart';

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
  get creationTime => keyPacket.creationTime;

  @override
  get expirationTime => BaseKey.keyExpiration(bindingSignatures);

  @override
  get fingerprint => keyPacket.fingerprint;

  @override
  get keyAlgorithm => keyPacket.keyAlgorithm;

  @override
  get keyID => keyPacket.keyID;

  @override
  get keyStrength => keyPacket.keyStrength;

  @override
  get isEncryptionKey {
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
  get isSigningKey {
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
  get packetList => PacketList([
        keyPacket,
        ...revocationSignatures,
        ...bindingSignatures,
      ]);

  @override
  get version => keyPacket.keyVersion;

  @override
  isRevoked([final DateTime? time]) {
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
  verify([final DateTime? time]) {
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
