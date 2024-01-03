// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enum/key_algorithm.dart';
import '../enum/revocation_reason_tag.dart';
import '../packet/key/key_id.dart';
import '../packet/key/key_params.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import '../packet/subkey_packet.dart';
import 'key.dart';

/// Class that represents a subkey packet and the relevant signatures.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class Subkey {
  /// subkey packet to hold in the Subkey
  final SubkeyPacket keyPacket;

  final Key? mainKey;

  final List<SignaturePacket> revocationSignatures;

  final List<SignaturePacket> bindingSignatures;

  Subkey(
    this.keyPacket, {
    this.mainKey,
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

  bool get isEncryptionKey {
    if (keyPacket.isEncryptionKey) {
      for (final signature in bindingSignatures) {
        if (signature.keyFlags != null &&
            !(signature.keyFlags!.isEncryptStorage ||
                signature.keyFlags!.isEncryptCommunication)) {
          return false;
        }
      }
    }
    return keyPacket.isEncryptionKey;
  }

  bool get isSigningKey {
    if (keyPacket.isSigningKey) {
      for (final signature in bindingSignatures) {
        if (signature.keyFlags != null && !signature.keyFlags!.isSignData) {
          return false;
        }
      }
    }
    return keyPacket.isSigningKey;
  }

  bool verify({
    final DateTime? date,
  }) {
    if (isRevoked(date: date)) {
      return false;
    }
    if (mainKey != null) {
      for (final signature in bindingSignatures) {
        if (!signature.verify(
          mainKey!.keyPacket,
          Uint8List.fromList([
            ...mainKey!.keyPacket.writeForSign(),
            ...keyPacket.writeForSign(),
          ]),
          date: date,
        )) {
          return false;
        }
      }
    }
    return true;
  }

  bool isRevoked({
    final SignaturePacket? signature,
    final DateTime? date,
  }) {
    if (mainKey != null && revocationSignatures.isNotEmpty) {
      for (var revocation in revocationSignatures) {
        if (signature == null ||
            revocation.issuerKeyID.id == signature.issuerKeyID.id) {
          if (revocation.verify(
            mainKey!.keyPacket,
            Uint8List.fromList([
              ...mainKey!.keyPacket.writeForSign(),
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

  Subkey revoke({
    RevocationReasonTag reason = RevocationReasonTag.noReason,
    String description = '',
    final DateTime? date,
  }) {
    if (mainKey != null && mainKey is PrivateKey) {
      return Subkey(
        keyPacket,
        mainKey: mainKey,
        revocationSignatures: [
          SignaturePacket.createSubkeyRevocation(
            (mainKey as PrivateKey).keyPacket,
            keyPacket,
            reason: reason,
            description: description,
            date: date,
          )
        ],
        bindingSignatures: bindingSignatures,
      );
    }
    return this;
  }

  DateTime? getExpirationTime() {
    bindingSignatures.sort(
      (a, b) => b.creationTime.creationTime.compareTo(
        a.creationTime.creationTime,
      ),
    );
    for (final signature in bindingSignatures) {
      if (signature.keyExpirationTime != null) {
        final expirationTime = signature.keyExpirationTime!.time;
        final creationTime = signature.creationTime.creationTime;
        return creationTime.add(Duration(seconds: expirationTime));
      }
    }
    return null;
  }
}
