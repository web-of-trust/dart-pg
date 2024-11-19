/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/type/key_packet.dart';

import '../common/helpers.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_type.dart';
import '../enum/signature_type.dart';
import '../type/signature_packet.dart';
import '../type/subpacket.dart';
import 'base.dart';
import 'public_key.dart';
import 'signature_subpacket.dart';

/// Implementation of the Signature Packet (Tag 2)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SignaturePacket extends BasePacket implements SignaturePacketInterface {
  @override
  final int version;

  @override
  final SignatureType signatureType;

  @override
  final KeyAlgorithm keyAlgorithm;

  @override
  final HashAlgorithm hashAlgorithm;

  @override
  final Uint8List signedHashValue;

  @override
  final Uint8List salt;

  @override
  final Uint8List signature;

  @override
  final Iterable<SubpacketInterface> hashedSubpackets;

  @override
  final Iterable<SubpacketInterface> unhashedSubpackets;

  @override
  final Uint8List signatureData;

  SignaturePacket(
    this.version,
    this.signatureType,
    this.keyAlgorithm,
    this.hashAlgorithm,
    this.signedHashValue,
    this.salt,
    this.signature, {
    this.hashedSubpackets = const [],
    this.unhashedSubpackets = const [],
  })  : signatureData = Uint8List.fromList([
          version,
          signatureType.value,
          keyAlgorithm.value,
          hashAlgorithm.value,
          ..._encodeSubpackets(hashedSubpackets),
        ]),
        super(PacketType.signature);

  @override
  Uint8List get data => Uint8List.fromList([]);

  @override
  DateTime? get creationTime => _getSubpacket<SignatureCreationTime>(
        hashedSubpackets,
      )?.creationTime;

  @override
  DateTime? get expirationTime => _getSubpacket<SignatureExpirationTime>(
        hashedSubpackets,
      )?.expirationTime;

  @override
  bool get isCertRevocation => signatureType == SignatureType.certRevocation;

  @override
  bool get isCertification => switch (signatureType) {
        SignatureType.certGeneric ||
        SignatureType.certPersona ||
        SignatureType.certCasual ||
        SignatureType.certPositive =>
          true,
        _ => false
      };

  @override
  bool get isDirectKey => signatureType == SignatureType.directKey;

  @override
  bool get isKeyRevocation => signatureType == SignatureType.keyRevocation;

  @override
  bool get isPrimaryUserID =>
      _getSubpacket<PrimaryUserID>(
        hashedSubpackets,
      )?.isPrimary ??
      false;

  @override
  bool get isSubkeyBinding => signatureType == SignatureType.subkeyBinding;

  @override
  bool get isSubkeyRevocation => signatureType == SignatureType.subkeyRevocation;

  @override
  Uint8List get issuerFingerprint {
    final subpacket = _getSubpacket<IssuerFingerprint>(
          hashedSubpackets,
        ) ??
        _getSubpacket<IssuerFingerprint>(
          unhashedSubpackets,
        );
    return subpacket?.fingerprint ?? Uint8List(version == 6 ? 32 : 20);
  }

  @override
  Uint8List get issuerKeyID {
    final subpacket = _getSubpacket<IssuerKeyID>(
          hashedSubpackets,
        ) ??
        _getSubpacket<IssuerKeyID>(
          unhashedSubpackets,
        );
    if (subpacket != null) {
      return subpacket.keyID;
    } else {
      return version == 6
          ? issuerFingerprint.sublist(0, PublicKeyPacket.keyIDSize)
          : issuerFingerprint.sublist(12, 12 + PublicKeyPacket.keyIDSize);
    }
  }

  @override
  bool isExpired([DateTime? time]) {
    // TODO: implement isExpired
    throw UnimplementedError();
  }

  @override
  bool verify(KeyPacketInterface verifyKey, Uint8List dataToVerify, [DateTime? time]) {
    // TODO: implement verify
    throw UnimplementedError();
  }

  static T? _getSubpacket<T extends SubpacketInterface>(
    final Iterable<SubpacketInterface> subpackets,
  ) {
    final typedSubpackets = subpackets.whereType<T>();
    return typedSubpackets.isNotEmpty ? typedSubpackets.first : null;
  }

  /// Encode subpacket to bytes
  static Uint8List _encodeSubpackets(
    final Iterable<SubpacketInterface> subpackets,
  ) {
    final bytes = subpackets
        .map(
          (subpacket) => subpacket.encode(),
        )
        .expand((byte) => byte);
    return Uint8List.fromList([...bytes.length.pack16(), ...bytes]);
  }
}
