/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/helpers.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/signature_subpacket_type.dart';
import '../enum/signature_type.dart';
import '../type/key_packet.dart';
import '../type/secret_key_packet.dart';
import '../type/signature_packet.dart';
import '../type/signing_key_material.dart';
import '../type/subpacket.dart';
import '../type/verification_key_material.dart';
import 'base.dart';
import 'signature_subpacket.dart';
import 'subpacket_reader.dart';

/// Implementation of the Signature (SIG) Packet - Type 2
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
          ..._encodeSubpackets(hashedSubpackets, version == 6),
        ]),
        super(PacketType.signature) {
    if (version != 4 && version != 6) {
      throw UnsupportedError(
        'Version $version of the signature packet is unsupported.',
      );
    }
  }

  factory SignaturePacket.fromBytes(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number (4 or 6).
    final version = bytes[pos++];
    final isV6 = version == 6;

    /// One-octet signature type.
    final signatureType = SignatureType.values.firstWhere(
      (type) => type.value == bytes[pos],
    );
    pos++;

    /// One-octet public-key algorithm.
    final keyAlgorithm = KeyAlgorithm.values.firstWhere(
      (alg) => alg.value == bytes[pos],
    );
    pos++;

    /// One-octet hash algorithm.
    final hashAlgorithm = HashAlgorithm.values.firstWhere(
      (alg) => alg.value == bytes[pos],
    );
    pos++;

    /// read hashed subpackets
    final hashedLength = isV6
        ? bytes
            .sublist(
              pos,
              pos + 4,
            )
            .unpack32()
        : bytes
            .sublist(
              pos,
              pos + 2,
            )
            .unpack16();
    pos += isV6 ? 4 : 2;
    final hashedSubpackets = _readSubpackets(
      bytes.sublist(pos, pos + hashedLength),
    );
    pos += hashedLength;

    /// read unhashed subpackets
    final unhashedLength = isV6
        ? bytes
            .sublist(
              pos,
              pos + 4,
            )
            .unpack32()
        : bytes
            .sublist(
              pos,
              pos + 2,
            )
            .unpack16();
    pos += isV6 ? 4 : 2;
    final unhashedSubpackets = _readSubpackets(
      bytes.sublist(pos, pos + unhashedLength),
    );
    pos += unhashedLength;

    /// Two-octet field holding left 16 bits of signed hash value.
    final signedHashValue = bytes.sublist(pos, pos + 2);
    pos += 2;

    final saltLength = isV6 ? bytes[pos++] : 0;
    final salt = bytes.sublist(pos, pos + saltLength);
    pos += saltLength;

    final signature = bytes.sublist(pos);

    return SignaturePacket(
      version,
      signatureType,
      keyAlgorithm,
      hashAlgorithm,
      signedHashValue,
      salt,
      signature,
      hashedSubpackets: hashedSubpackets,
      unhashedSubpackets: unhashedSubpackets,
    );
  }

  factory SignaturePacket.createSignature(
    SecretKeyPacketInterface signKey,
    SignatureType signatureType,
    Uint8List dataToSign, {
    final HashAlgorithm? preferredHash,
    final Iterable<SubpacketInterface> subpackets = const [],
    final int keyExpirationTime = 0,
    final DateTime? date,
  }) {
    final version = signKey.keyVersion;
    final keyAlgorithm = signKey.keyAlgorithm;
    final hashAlgorithm = preferredHash ?? signKey.preferredHash;
    Helper.assertHash(hashAlgorithm);

    final hashedSubpackets = [
      SignatureCreationTime.fromTime(date ?? DateTime.now()),
      IssuerFingerprint.fromKey(signKey),
      IssuerKeyID(signKey.keyID),
      ...subpackets,
    ];
    if (version == 4) {
      hashedSubpackets.add(NotationData.saltNotation(hashAlgorithm.saltSize));
    }
    if (keyExpirationTime > 0) {
      hashedSubpackets.add(KeyExpirationTime.fromTime(keyExpirationTime));
    }
    final salt = version == 6
        ? Helper.randomBytes(
            hashAlgorithm.saltSize,
          )
        : Uint8List(0);

    final signatureData = Uint8List.fromList([
      version,
      signatureType.value,
      keyAlgorithm.value,
      hashAlgorithm.value,
      ..._encodeSubpackets(hashedSubpackets, version == 6),
    ]);

    final message = Uint8List.fromList([
      ...salt,
      ...dataToSign,
      ...signatureData,
      ..._calculateTrailer(
        version,
        signatureData.length,
      )
    ]);

    return SignaturePacket(
      version,
      signatureType,
      keyAlgorithm,
      hashAlgorithm,
      Helper.hashDigest(message, hashAlgorithm).sublist(0, 2),
      salt,
      _signMessage(signKey, hashAlgorithm, message),
      hashedSubpackets: hashedSubpackets,
    );
  }

  @override
  Uint8List get data => Uint8List.fromList([
        ...signatureData,
        ..._encodeSubpackets(unhashedSubpackets, version == 6),
        ...signedHashValue,
        ...version == 6 ? [salt.length] : [],
        ...version == 6 ? salt : [],
        ...signature,
      ]);

  @override
  DateTime? get creationTime => getSubpacket<SignatureCreationTime>()?.creationTime;

  @override
  DateTime? get expirationTime => getSubpacket<SignatureExpirationTime>()?.expirationTime;

  @override
  int get keyExpirationTime => getSubpacket<KeyExpirationTime>()?.expiry ?? 0;

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
  bool get isPrimaryUserID => getSubpacket<PrimaryUserID>()?.isPrimary ?? false;

  @override
  bool get isSubkeyBinding => signatureType == SignatureType.subkeyBinding;

  @override
  bool get isSubkeyRevocation => signatureType == SignatureType.subkeyRevocation;

  @override
  Uint8List get issuerFingerprint =>
      getSubpacket<IssuerFingerprint>()?.fingerprint ?? Uint8List(version == 6 ? 32 : 20);

  @override
  Uint8List get issuerKeyID {
    final subpacket = getSubpacket<IssuerKeyID>();
    if (subpacket != null) {
      return subpacket.keyID;
    } else {
      return version == 6
          ? issuerFingerprint.sublist(0, PublicKeyPacket.keyIDSize)
          : issuerFingerprint.sublist(12, 12 + PublicKeyPacket.keyIDSize);
    }
  }

  @override
  T? getSubpacket<T extends SubpacketInterface>() {
    return hashedSubpackets.whereType<T>().elementAtOrNull(0) ?? unhashedSubpackets.whereType<T>().elementAtOrNull(0);
  }

  @override
  bool isExpired([final DateTime? time]) {
    final timestamp = time?.millisecondsSinceEpoch ?? DateTime.now().millisecondsSinceEpoch;
    final creation = creationTime?.millisecondsSinceEpoch ?? 0;
    final expiration = expirationTime?.millisecondsSinceEpoch ?? DateTime.now().millisecondsSinceEpoch;
    return !(creation <= timestamp && timestamp <= expiration);
  }

  @override
  bool verify(
    final KeyPacketInterface verifyKey,
    final Uint8List dataToVerify, [
    final DateTime? time,
  ]) {
    if (!issuerKeyID.equals(verifyKey.keyID)) {
      throw ArgumentError('Signature was not issued by the given public key.');
    }
    if (keyAlgorithm != verifyKey.keyAlgorithm) {
      throw ArgumentError(
        'Public key algorithm used to sign signature does not match issuer key algorithm.',
      );
    }
    if (isExpired(time)) {
      throw StateError('Signature is expired.');
    }

    final message = Uint8List.fromList([
      ...salt,
      ...dataToVerify,
      ...signatureData,
      ..._calculateTrailer(
        version,
        signatureData.length,
      )
    ]);

    final hash = Helper.hashDigest(message, hashAlgorithm);
    if (signedHashValue[0] != hash[0] || signedHashValue[1] != hash[1]) {
      throw StateError('Signed digest did not match!');
    }

    final keyMaterial = verifyKey.keyMaterial;
    if (keyMaterial is VerificationKeyMaterial) {
      return keyMaterial.verify(message, hashAlgorithm, signature);
    } else {
      throw UnsupportedError(
        'Unsupported public key algorithm for verification.',
      );
    }
  }

  static Uint8List _signMessage(
    final SecretKeyPacketInterface key,
    final HashAlgorithm hash,
    final Uint8List message,
  ) {
    final keyMaterial = key.secretKeyMaterial;
    if (keyMaterial is SigningKeyMaterialInterface) {
      return keyMaterial.sign(message, hash);
    } else {
      throw UnsupportedError(
        'Unsupported public key algorithm for signing.',
      );
    }
  }

  static Iterable<SubpacketInterface> _readSubpackets(final Uint8List bytes) {
    final subpackets = <SubpacketInterface>[];
    var offset = 0;
    while (offset < bytes.length) {
      final reader = SubpacketReader.read(bytes, offset);
      offset = reader.offset;
      final data = reader.data;
      if (data.isNotEmpty) {
        final critical = ((reader.type & 0x80) != 0);
        final type = SignatureSubpacketType.values.firstWhere(
          (type) => type.value == (reader.type & 0x7f),
        );
        switch (type) {
          case SignatureSubpacketType.signatureCreationTime:
            subpackets.add(SignatureCreationTime(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.signatureExpirationTime:
            subpackets.add(SignatureExpirationTime(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.exportableCertification:
            subpackets.add(ExportableCertification(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.trustSignature:
            subpackets.add(TrustSignature(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.regularExpression:
            subpackets.add(RegularExpression(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.revocable:
            subpackets.add(Revocable(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.keyExpirationTime:
            subpackets.add(KeyExpirationTime(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.preferredSymmetricAlgorithms:
            subpackets.add(PreferredSymmetricAlgorithms(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.revocationKey:
            subpackets.add(RevocationKey(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.issuerKeyID:
            subpackets.add(IssuerKeyID(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.notationData:
            subpackets.add(NotationData(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.preferredHashAlgorithms:
            subpackets.add(PreferredHashAlgorithms(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.preferredCompressionAlgorithms:
            subpackets.add(PreferredCompressionAlgorithms(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.keyServerPreferences:
            subpackets.add(KeyServerPreferences(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.preferredKeyServer:
            subpackets.add(PreferredKeyServer(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.primaryUserID:
            subpackets.add(PrimaryUserID(data, critical: critical));
            break;
          case SignatureSubpacketType.policyURI:
            subpackets.add(PolicyURI(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.keyFlags:
            subpackets.add(KeyFlags(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.signerUserID:
            subpackets.add(SignerUserID(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.revocationReason:
            subpackets.add(RevocationReason(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.features:
            subpackets.add(Features(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.signatureTarget:
            subpackets.add(SignatureTarget(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.embeddedSignature:
            subpackets.add(EmbeddedSignature(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.issuerFingerprint:
            subpackets.add(IssuerFingerprint(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.preferredAeadAlgorithms:
            subpackets.add(PreferredAeadAlgorithms(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.intendedRecipientFingerprint:
            subpackets.add(IntendedRecipientFingerprint(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          case SignatureSubpacketType.preferredAeadCiphers:
            subpackets.add(PreferredAeadCiphers(
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
            break;
          default:
            subpackets.add(SignatureSubpacket(
              type,
              data,
              critical: critical,
              isLong: reader.isLong,
            ));
        }
      }
    }
    return subpackets;
  }

  static Uint8List _calculateTrailer(
    final int version,
    final int dataLength,
  ) {
    return Uint8List.fromList([
      version,
      0xff,
      ...dataLength.pack32(),
    ]);
  }

  /// Encode subpacket to bytes
  static Uint8List _encodeSubpackets(
    final Iterable<SubpacketInterface> subpackets,
    bool isV6,
  ) {
    final bytes = subpackets
        .map(
          (subpacket) => subpacket.encode(),
        )
        .expand((byte) => byte);
    return Uint8List.fromList([
      ...isV6 ? bytes.length.pack32() : bytes.length.pack16(),
      ...bytes,
    ]);
  }
}
