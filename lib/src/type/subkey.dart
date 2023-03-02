// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../packet/key/key_id.dart';
import '../packet/key/key_params.dart';
import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import '../packet/subkey_packet.dart';

/// Class that represents a subkey packet and the relevant signatures.
class Subkey {
  /// subkey packet to hold in the Subkey
  final SubkeyPacket keyPacket;

  final List<SignaturePacket> revocationSignatures;

  final List<SignaturePacket> bindingSignatures;

  Subkey(
    this.keyPacket, {
    this.revocationSignatures = const [],
    this.bindingSignatures = const [],
  });

  DateTime get creationTime => keyPacket.creationTime;

  KeyAlgorithm get algorithm => keyPacket.algorithm;

  String get fingerprint => keyPacket.fingerprint;

  KeyID get keyID => keyPacket.keyID;

  KeyParams get publicParams => keyPacket.publicParams;

  int get keyStrength => keyPacket.keyStrength;

  PacketList toPacketList() {
    return PacketList([
      keyPacket,
      ...revocationSignatures,
      ...bindingSignatures,
    ]);
  }

  bool get isSigningKey {
    if (keyPacket is PublicKeyPacket) {
      return false;
    }
    bool isSigning;
    switch (keyPacket.algorithm) {
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.elgamal:
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.diffieHellman:
      case KeyAlgorithm.aedh:
        isSigning = false;
        break;
      default:
        isSigning = true;
        for (final signature in bindingSignatures) {
          if (signature.keyFlags == null) {
            continue;
          } else if ((signature.keyFlags!.flags & KeyFlag.signData.value) == 0) {
            isSigning = false;
            break;
          }
        }
    }
    return isSigning;
  }

  bool get isEncryptionKey {
    if (keyPacket is SecretKeyPacket) {
      return false;
    }
    bool isEncryption;
    switch (keyPacket.algorithm) {
      case KeyAlgorithm.rsaSign:
      case KeyAlgorithm.dsa:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
      case KeyAlgorithm.aedsa:
        isEncryption = false;
        break;
      default:
        isEncryption = true;
        for (final signature in bindingSignatures) {
          if (signature.keyFlags == null) {
            continue;
          } else if ((signature.keyFlags!.flags & KeyFlag.signData.value) == KeyFlag.signData.value) {
            isEncryption = false;
            break;
          }
        }
    }
    return isEncryption;
  }

  bool verify(
    KeyPacket primaryKey, {
    final DateTime? date,
  }) {
    if (isRevoked(primaryKey, date: date)) {
      return false;
    }
    for (final signature in bindingSignatures) {
      if (!signature.verify(
        primaryKey,
        Uint8List.fromList([
          ...primaryKey.writeForSign(),
          ...keyPacket.writeForSign(),
        ]),
        date: date,
      )) {
        return false;
      }
    }
    return true;
  }

  bool isRevoked(
    KeyPacket primaryKey, {
    SignaturePacket? signature,
    final DateTime? date,
  }) {
    if (revocationSignatures.isNotEmpty) {
      for (var revocation in revocationSignatures) {
        if (signature == null || revocation.issuerKeyID.keyID == signature.issuerKeyID.keyID) {
          if (revocation.verify(
            primaryKey,
            Uint8List.fromList([
              ...primaryKey.writeForSign(),
              ...keyPacket.writeForSign(),
            ]),
            date: date,
          )) {
            return true;
          }
        }
      }
    }
    return false;
  }
}
