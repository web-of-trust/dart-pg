// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/math/byte_ext.dart';
import '../crypto/math/int_ext.dart';
import '../enum/compression_algorithm.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/key_flag.dart';
import '../enum/literal_format.dart';
import '../enum/packet_tag.dart';
import '../enum/revocation_reason_tag.dart';
import '../enum/signature_subpacket_type.dart';
import '../enum/signature_type.dart';
import '../enum/support_feature.dart';
import '../enum/symmetric_algorithm.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'key/key_params.dart';
import 'key_packet.dart';
import 'literal_data.dart';
import 'signature_subpacket.dart';
import 'subpacket_reader.dart';
import 'user_attribute.dart';
import 'user_id.dart';

/// Signature represents a signature.
/// See RFC 4880, section 5.2.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SignaturePacket extends ContainedPacket {
  final int version;

  final SignatureType signatureType;

  final KeyAlgorithm keyAlgorithm;

  final HashAlgorithm hashAlgorithm;

  final Uint8List signatureData;

  final Uint8List signedHashValue;

  final Uint8List signature;

  final List<SignatureSubpacket> hashedSubpackets;

  final List<SignatureSubpacket> unhashedSubpackets;

  SignaturePacket(
    this.version,
    this.signatureType,
    this.keyAlgorithm,
    this.hashAlgorithm,
    this.signedHashValue,
    this.signature, {
    this.hashedSubpackets = const [],
    this.unhashedSubpackets = const [],
  })  : signatureData = Uint8List.fromList([
          version,
          signatureType.value,
          keyAlgorithm.value,
          hashAlgorithm.value,
          ..._writeSubpackets(hashedSubpackets),
        ]),
        super(PacketTag.signature);

  SignatureCreationTime get creationTime =>
      _getSubpacket<SignatureCreationTime>(hashedSubpackets) ??
      SignatureCreationTime.fromTime(DateTime.now());

  IssuerKeyID get issuerKeyID {
    final issuerKeyID = _getSubpacket<IssuerKeyID>(hashedSubpackets) ??
        _getSubpacket<IssuerKeyID>(unhashedSubpackets);
    if (issuerKeyID != null) {
      return issuerKeyID;
    } else if (issuerFingerprint != null) {
      final fingerprint = issuerFingerprint!.data.sublist(1);
      return IssuerKeyID(fingerprint.sublist(12, 20));
    } else {
      return IssuerKeyID.wildcard();
    }
  }

  SignatureExpirationTime? get signatureExpirationTime =>
      _getSubpacket<SignatureExpirationTime>(hashedSubpackets);

  ExportableCertification? get exportable =>
      _getSubpacket<ExportableCertification>(hashedSubpackets);

  TrustSignature? get trustSignature =>
      _getSubpacket<TrustSignature>(hashedSubpackets);

  RegularExpression? get regularExpression =>
      _getSubpacket<RegularExpression>(hashedSubpackets);

  Revocable? get revocable => _getSubpacket<Revocable>(hashedSubpackets);

  KeyExpirationTime? get keyExpirationTime =>
      _getSubpacket<KeyExpirationTime>(hashedSubpackets);

  PreferredSymmetricAlgorithms? get preferredSymmetricAlgorithms =>
      _getSubpacket<PreferredSymmetricAlgorithms>(hashedSubpackets);

  RevocationKey? get revocationKey =>
      _getSubpacket<RevocationKey>(hashedSubpackets);

  NotationData? get notationData =>
      _getSubpacket<NotationData>(hashedSubpackets);

  PreferredHashAlgorithms? get preferredHashAlgorithms =>
      _getSubpacket<PreferredHashAlgorithms>(hashedSubpackets);

  PreferredCompressionAlgorithms? get preferredCompressionAlgorithms =>
      _getSubpacket<PreferredCompressionAlgorithms>(hashedSubpackets);

  KeyServerPreferences? get keyServerPreferences =>
      _getSubpacket<KeyServerPreferences>(hashedSubpackets);

  PreferredKeyServer? get preferredKeyServer =>
      _getSubpacket<PreferredKeyServer>(hashedSubpackets);

  PrimaryUserID? get primaryUserID =>
      _getSubpacket<PrimaryUserID>(hashedSubpackets);

  PolicyURI? get policyURI => _getSubpacket<PolicyURI>(hashedSubpackets);

  KeyFlags? get keyFlags => _getSubpacket<KeyFlags>(hashedSubpackets);

  SignerUserID? get signerUserID =>
      _getSubpacket<SignerUserID>(hashedSubpackets);

  RevocationReason? get revocationReason =>
      _getSubpacket<RevocationReason>(hashedSubpackets);

  Features? get features => _getSubpacket<Features>(hashedSubpackets);

  SignatureTarget? get signatureTarget =>
      _getSubpacket<SignatureTarget>(hashedSubpackets);

  EmbeddedSignature? get embeddedSignature =>
      _getSubpacket<EmbeddedSignature>(hashedSubpackets);

  IssuerFingerprint? get issuerFingerprint =>
      _getSubpacket<IssuerFingerprint>(hashedSubpackets) ??
      _getSubpacket<IssuerFingerprint>(unhashedSubpackets);

  bool get signatureNeverExpires => signatureExpirationTime == null;

  bool get keyNeverExpires => keyExpirationTime == null;

  factory SignaturePacket.fromByteData(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number (3 or 4 or 5).
    final version = bytes[pos++];
    if (version != 4) {
      throw UnsupportedError(
        'Version $version of the signature packet is unsupported.',
      );
    }

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
    final hashedLength = bytes.sublist(pos, pos + 2).toUint16();
    pos += 2;
    final hashedSubpackets = _readSubpackets(
      bytes.sublist(pos, pos + hashedLength),
    );
    pos += hashedLength;

    /// read unhashed subpackets
    final unhashedLength = bytes.sublist(pos, pos + 2).toUint16();
    pos += 2;
    final unhashedSubpackets = _readSubpackets(
      bytes.sublist(pos, pos + unhashedLength),
    );
    pos += unhashedLength;

    /// Two-octet field holding left 16 bits of signed hash value.
    final signedHashValue = bytes.sublist(pos, pos + 2);
    pos += 2;
    final signature = bytes.sublist(pos);

    return SignaturePacket(
      version,
      signatureType,
      keyAlgorithm,
      hashAlgorithm,
      signedHashValue,
      signature,
      hashedSubpackets: hashedSubpackets,
      unhashedSubpackets: unhashedSubpackets,
    );
  }

  static SignaturePacket createSignature(
    final SecretKeyPacket signKey,
    final SignatureType signatureType,
    final Uint8List dataToSign, {
    final HashAlgorithm? preferredHash,
    final List<SignatureSubpacket> subpackets = const [],
    final int keyExpirationTime = 0,
    final DateTime? date,
  }) {
    final version = signKey.version;
    final keyAlgorithm = signKey.algorithm;
    final hashAlgorithm = preferredHash ?? signKey.preferredHash;

    final hashedSubpackets = [
      SignatureCreationTime.fromTime(date ?? DateTime.now()),
      IssuerFingerprint.fromKey(signKey),
      IssuerKeyID(signKey.keyID.bytes),
      NotationData.saltNotation(hashAlgorithm.saltSize),
      ...subpackets,
    ];
    if (keyExpirationTime > 0) {
      hashedSubpackets.add(KeyExpirationTime.fromTime(keyExpirationTime));
    }

    final signatureData = Uint8List.fromList([
      version,
      signatureType.value,
      keyAlgorithm.value,
      hashAlgorithm.value,
      ..._writeSubpackets(hashedSubpackets),
    ]);
    final message = Uint8List.fromList([
      ...dataToSign,
      ...signatureData,
      ..._calculateTrailer(
        version,
        signatureData.lengthInBytes,
      )
    ]);
    return SignaturePacket(
      version,
      signatureType,
      keyAlgorithm,
      hashAlgorithm,
      Helper.hashDigest(message, hashAlgorithm).sublist(0, 2),
      _signMessage(signKey, hashAlgorithm, message),
      hashedSubpackets: hashedSubpackets,
    );
  }

  static SignaturePacket createSelfCertificate(
    final SecretKeyPacket signKey, {
    final HashAlgorithm? preferredHash,
    final UserIDPacket? userID,
    final UserAttributePacket? userAttribute,
    final int keyExpirationTime = 0,
    final DateTime? date,
  }) {
    final bytes = userID?.writeForSign() ?? userAttribute?.writeForSign();
    if (bytes == null) {
      throw ArgumentError(
        'Either a userID or userAttribute packet needs to be supplied for certification.',
      );
    }
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.certGeneric,
      Uint8List.fromList([
        ...signKey.writeForSign(),
        ...bytes,
      ]),
      subpackets: [
        KeyFlags.fromFlags(KeyFlag.certifyKeys.value | KeyFlag.signData.value),
        PreferredSymmetricAlgorithms(Uint8List.fromList([
          SymmetricAlgorithm.aes128.value,
          SymmetricAlgorithm.aes192.value,
          SymmetricAlgorithm.aes256.value,
        ])),
        PreferredHashAlgorithms(Uint8List.fromList([
          HashAlgorithm.sha256.value,
          HashAlgorithm.sha512.value,
        ])),
        PreferredCompressionAlgorithms(Uint8List.fromList([
          CompressionAlgorithm.zlib.value,
          CompressionAlgorithm.zip.value,
          CompressionAlgorithm.uncompressed.value,
        ])),
        Features(Uint8List.fromList([
          SupportFeature.modificationDetection.value,
          SupportFeature.aeadEncryptedData.value,
        ])),
      ],
      preferredHash: preferredHash,
      keyExpirationTime: keyExpirationTime,
      date: date,
    );
  }

  static SignaturePacket createCertifySignature(
    final SecretKeyPacket signKey, {
    final HashAlgorithm? preferredHash,
    final UserIDPacket? userID,
    final UserAttributePacket? userAttribute,
    final int keyExpirationTime = 0,
    final DateTime? date,
  }) {
    final bytes = userID?.writeForSign() ?? userAttribute?.writeForSign();
    if (bytes == null) {
      throw ArgumentError(
        'Either a userID or userAttribute packet needs to be supplied for certification.',
      );
    }
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.certGeneric,
      Uint8List.fromList([
        ...signKey.writeForSign(),
        ...bytes,
      ]),
      subpackets: [
        KeyFlags.fromFlags(KeyFlag.certifyKeys.value | KeyFlag.signData.value),
      ],
      preferredHash: preferredHash,
      keyExpirationTime: keyExpirationTime,
      date: date,
    );
  }

  static SignaturePacket createKeyBinding(
    final SecretKeyPacket signKey,
    final KeyPacket bindKey, {
    final HashAlgorithm? preferredHash,
    final int keyExpirationTime = 0,
    final DateTime? date,
  }) {
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.keyBinding,
      Uint8List.fromList([
        ...signKey.writeForSign(),
        ...bindKey.writeForSign(),
      ]),
      preferredHash: preferredHash,
      keyExpirationTime: keyExpirationTime,
      date: date,
    );
  }

  static SignaturePacket createSubkeyBinding(
    final SecretKeyPacket signKey,
    final SecretSubkeyPacket subkey, {
    final HashAlgorithm? preferredHash,
    final int keyExpirationTime = 0,
    final bool subkeySign = false,
    final DateTime? date,
  }) {
    final subpackets = <SignatureSubpacket>[];
    if (subkeySign) {
      subpackets.add(KeyFlags.fromFlags(KeyFlag.signData.value));
      subpackets.add(EmbeddedSignature.fromSignature(
        SignaturePacket.createSignature(
          subkey,
          SignatureType.keyBinding,
          Uint8List.fromList([
            ...signKey.writeForSign(),
            ...subkey.writeForSign(),
          ]),
          keyExpirationTime: keyExpirationTime,
          date: date,
        ),
      ));
    } else {
      subpackets.add(
        KeyFlags.fromFlags(
          KeyFlag.encryptCommunication.value | KeyFlag.encryptStorage.value,
        ),
      );
    }
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.subkeyBinding,
      Uint8List.fromList([
        ...signKey.writeForSign(),
        ...subkey.writeForSign(),
      ]),
      subpackets: subpackets,
      preferredHash: preferredHash ?? subkey.preferredHash,
      keyExpirationTime: keyExpirationTime,
      date: date,
    );
  }

  static SignaturePacket createKeyRevocation(
    final SecretKeyPacket signKey, {
    final HashAlgorithm? preferredHash,
    final RevocationReasonTag reason = RevocationReasonTag.noReason,
    final String description = '',
    final DateTime? date,
  }) {
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.keyRevocation,
      Uint8List.fromList([
        ...signKey.writeForSign(),
      ]),
      preferredHash: preferredHash,
      subpackets: [RevocationReason.fromRevocation(reason, description)],
      date: date,
    );
  }

  static SignaturePacket createSubkeyRevocation(
    final SecretKeyPacket signKey,
    final SubkeyPacket subKey, {
    final HashAlgorithm? preferredHash,
    final RevocationReasonTag reason = RevocationReasonTag.noReason,
    final String description = '',
    final DateTime? date,
  }) {
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.subkeyRevocation,
      Uint8List.fromList([
        ...signKey.writeForSign(),
        ...subKey.writeForSign(),
      ]),
      preferredHash: preferredHash,
      subpackets: [RevocationReason.fromRevocation(reason, description)],
      date: date,
    );
  }

  static SignaturePacket createLiteralData(
    final SecretKeyPacket signKey,
    final LiteralDataPacket literalData, {
    final HashAlgorithm? preferredHash,
    final DateTime? date,
  }) {
    final SignatureType signatureType;
    switch (literalData.format) {
      case LiteralFormat.text:
      case LiteralFormat.utf8:
        signatureType = SignatureType.text;
        break;
      default:
        signatureType = SignatureType.binary;
    }
    return SignaturePacket.createSignature(
      signKey,
      signatureType,
      literalData.writeForSign(),
      preferredHash: preferredHash,
      date: date,
    );
  }

  @override
  Uint8List toByteData() => Uint8List.fromList([
        ...signatureData,
        ..._writeSubpackets(unhashedSubpackets),
        ...signedHashValue,
        ...signature,
      ]);

  /// Verifies the signature packet.
  bool verify(
    final KeyPacket verifyKey,
    final Uint8List dataToVerify, {
    final DateTime? date,
  }) {
    if (issuerKeyID.id != verifyKey.keyID.toString()) {
      throw ArgumentError('Signature was not issued by the given public key.');
    }
    if (keyAlgorithm != verifyKey.algorithm) {
      throw ArgumentError(
        'Public key algorithm used to sign signature does not match issuer key algorithm.',
      );
    }
    if (signatureExpirationTime != null &&
        signatureExpirationTime!.expirationTime
                .compareTo(date ?? DateTime.now()) <
            0) {
      /// Signature is expired
      return false;
    }

    final message = Uint8List.fromList([
      ...dataToVerify,
      ...signatureData,
      ..._calculateTrailer(
        version,
        signatureData.lengthInBytes,
      )
    ]);
    final hash = Helper.hashDigest(message, hashAlgorithm);
    if (signedHashValue[0] != hash[0] || signedHashValue[1] != hash[1]) {
      throw StateError('Signed digest did not match');
    }

    final keyParams = verifyKey.publicParams;
    if (keyParams is VerificationParams) {
      return keyParams.verify(message, hashAlgorithm, signature);
    } else {
      throw UnsupportedError(
        'Unsupported public key algorithm for verification.',
      );
    }
  }

  bool verifyUserCertification(
    final KeyPacket verifyKey, {
    final UserIDPacket? userID,
    final UserAttributePacket? userAttribute,
    final DateTime? date,
  }) {
    final bytes = userID?.writeForSign() ?? userAttribute?.writeForSign();
    if (bytes == null) {
      throw ArgumentError(
        'Either a userID or userAttribute packet needs to be supplied for certification.',
      );
    }
    return verify(
      verifyKey,
      Uint8List.fromList([
        ...verifyKey.writeForSign(),
        ...bytes,
      ]),
      date: date,
    );
  }

  bool verifyLiteralData(
    final KeyPacket verifyKey,
    final LiteralDataPacket literalData, {
    final DateTime? date,
  }) {
    return verify(
      verifyKey,
      literalData.writeForSign(),
      date: date,
    );
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

  /// Signs provided data. This needs to be done prior to serialization.
  static Uint8List _signMessage(
    final SecretKeyPacket key,
    final HashAlgorithm hash,
    final Uint8List message,
  ) {
    switch (key.algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaSign:
        return (key.secretParams as RSASecretParams).sign(message, hash);
      case KeyAlgorithm.dsa:
        return (key.secretParams as DSASecretParams).sign(
          key.publicParams as DSAPublicParams,
          message,
          hash,
        );
      case KeyAlgorithm.ecdsa:
        return (key.secretParams as ECSecretParams).sign(
          key.publicParams as ECPublicParams,
          message,
          hash,
        );
      case KeyAlgorithm.eddsa:
        return (key.secretParams as EdSecretParams).sign(message, hash);
      default:
        throw UnsupportedError(
          'Unsupported public key algorithm for signing.',
        );
    }
  }

  /// Creates list of bytes with subpacket data
  static Uint8List _writeSubpackets(
      final Iterable<SignatureSubpacket> subpackets) {
    final bytes = subpackets
        .map((subpacket) => subpacket.encode())
        .expand((byte) => byte);
    return Uint8List.fromList([...bytes.length.pack16(), ...bytes]);
  }

  /// Reads V4 signature sub packets
  static List<SignatureSubpacket> _readSubpackets(final Uint8List bytes) {
    final subpackets = <SignatureSubpacket>[];
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

  static T? _getSubpacket<T extends SignatureSubpacket>(
    final List<SignatureSubpacket> subpackets,
  ) {
    final typedSubpackets = subpackets.whereType<T>();
    return typedSubpackets.isNotEmpty ? typedSubpackets.first : null;
  }
}
