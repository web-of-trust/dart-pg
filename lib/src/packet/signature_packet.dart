// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../crypto/signer/dsa.dart';
import '../enums.dart';
import '../helpers.dart';
import '../openpgp.dart';
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
    super.tag = PacketTag.signature,
  }) : signatureData = Uint8List.fromList([
          version,
          signatureType.value,
          keyAlgorithm.value,
          hashAlgorithm.value,
          ..._writeSubpackets(hashedSubpackets),
        ]);

  SignatureCreationTime get creationTime =>
      _getSubpacket<SignatureCreationTime>(hashedSubpackets) ?? SignatureCreationTime.fromTime(DateTime.now());

  IssuerKeyID get issuerKeyID {
    final issuerKeyID = _getSubpacket<IssuerKeyID>(hashedSubpackets) ?? _getSubpacket<IssuerKeyID>(unhashedSubpackets);
    if (issuerKeyID != null) {
      return issuerKeyID;
    } else if (issuerFingerprint != null) {
      final fingerprint = issuerFingerprint!.data.sublist(1);
      if (issuerFingerprint!.keyVersion == 5) {
        return IssuerKeyID(fingerprint.sublist(0, 8));
      } else {
        return IssuerKeyID(fingerprint.sublist(12, 20));
      }
    } else {
      return IssuerKeyID.wildcard();
    }
  }

  SignatureExpirationTime? get signatureExpirationTime => _getSubpacket<SignatureExpirationTime>(hashedSubpackets);

  ExportableCertification? get exportable => _getSubpacket<ExportableCertification>(hashedSubpackets);

  TrustSignature? get trustSignature => _getSubpacket<TrustSignature>(hashedSubpackets);

  RegularExpression? get regularExpression => _getSubpacket<RegularExpression>(hashedSubpackets);

  Revocable? get revocable => _getSubpacket<Revocable>(hashedSubpackets);

  KeyExpirationTime? get keyExpirationTime => _getSubpacket<KeyExpirationTime>(hashedSubpackets);

  PreferredSymmetricAlgorithms? get preferredSymmetricAlgorithms =>
      _getSubpacket<PreferredSymmetricAlgorithms>(hashedSubpackets);

  RevocationKey? get revocationKey => _getSubpacket<RevocationKey>(hashedSubpackets);

  NotationData? get notationData => _getSubpacket<NotationData>(hashedSubpackets);

  PreferredHashAlgorithms? get preferredHashAlgorithms => _getSubpacket<PreferredHashAlgorithms>(hashedSubpackets);

  PreferredCompressionAlgorithms? get preferredCompressionAlgorithms =>
      _getSubpacket<PreferredCompressionAlgorithms>(hashedSubpackets);

  KeyServerPreferences? get keyServerPreferences => _getSubpacket<KeyServerPreferences>(hashedSubpackets);

  PreferredKeyServer? get preferredKeyServer => _getSubpacket<PreferredKeyServer>(hashedSubpackets);

  PrimaryUserID? get primaryUserID => _getSubpacket<PrimaryUserID>(hashedSubpackets);

  PolicyURI? get policyURI => _getSubpacket<PolicyURI>(hashedSubpackets);

  KeyFlags? get keyFlags => _getSubpacket<KeyFlags>(hashedSubpackets);

  SignerUserID? get signerUserID => _getSubpacket<SignerUserID>(hashedSubpackets);

  RevocationReason? get revocationReason => _getSubpacket<RevocationReason>(hashedSubpackets);

  Features? get features => _getSubpacket<Features>(hashedSubpackets);

  SignatureTarget? get signatureTarget => _getSubpacket<SignatureTarget>(hashedSubpackets);

  EmbeddedSignature? get embeddedSignature => _getSubpacket<EmbeddedSignature>(hashedSubpackets);

  IssuerFingerprint? get issuerFingerprint =>
      _getSubpacket<IssuerFingerprint>(hashedSubpackets) ?? _getSubpacket<IssuerFingerprint>(unhashedSubpackets);

  PreferredAEADAlgorithms? get preferredAEADAlgorithms => _getSubpacket<PreferredAEADAlgorithms>(hashedSubpackets);

  bool get signatureNeverExpires => signatureExpirationTime == null;

  bool get keyNeverExpires => keyExpirationTime == null;

  factory SignaturePacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    if (version != 4 && version != 5) {
      throw UnsupportedError('Version $version of the signature packet is unsupported.');
    }

    /// One-octet signature type.
    final signatureType = SignatureType.values.firstWhere((type) => type.value == bytes[pos]);
    pos++;

    /// One-octet public-key algorithm.
    final keyAlgorithm = KeyAlgorithm.values.firstWhere((alg) => alg.value == bytes[pos]);
    pos++;

    /// One-octet hash algorithm.
    final hashAlgorithm = HashAlgorithm.values.firstWhere((alg) => alg.value == bytes[pos]);
    pos++;

    /// read hashed subpackets
    final hashedLength = bytes.sublist(pos, pos + 2).toUint16();
    pos += 2;
    final hashedSubpackets = _readSubpackets(bytes.sublist(pos, pos + hashedLength));
    pos += hashedLength;

    /// read unhashed subpackets
    final unhashedLength = bytes.sublist(pos, pos + 2).toUint16();
    pos += 2;
    final unhashedSubpackets = _readSubpackets(bytes.sublist(pos, pos + unhashedLength));
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

  factory SignaturePacket.createSignature(
    final SecretKeyPacket signKey,
    final SignatureType signatureType,
    final Uint8List dataToSign, {
    final HashAlgorithm? preferredHash,
    List<SignatureSubpacket> subpackets = const [],
    final int keyExpirationTime = 0,
    final DateTime? date,
    final Uint8List? attachedHeader,
  }) {
    final version = signKey.version;
    final keyAlgorithm = signKey.algorithm;
    final hashAlgorithm = preferredHash ?? _getPreferredHash(signKey);

    final hashedSubpackets = [
      SignatureCreationTime.fromTime(date ?? DateTime.now()),
      IssuerFingerprint.fromKey(signKey),
      IssuerKeyID(signKey.keyID.id),
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
        signatureType,
        signatureData,
        version,
        attachedHeader: attachedHeader,
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

  factory SignaturePacket.createSelfCertificate(
    final SecretKeyPacket signKey, {
    final UserIDPacket? userID,
    final UserAttributePacket? userAttribute,
    final int keyExpirationTime = 0,
    final DateTime? date,
  }) {
    final bytes = userID?.writeForSign() ?? userAttribute?.writeForSign();
    if (bytes == null) {
      throw ArgumentError('Either a userID or userAttribute packet needs to be supplied for certification.');
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
        ])),
      ],
      keyExpirationTime: keyExpirationTime,
      date: date,
    );
  }

  factory SignaturePacket.createKeyBinding(
    final SecretKeyPacket signKey,
    final KeyPacket bindKey, {
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
      keyExpirationTime: keyExpirationTime,
      date: date,
    );
  }

  factory SignaturePacket.createSubkeyBinding(
    final SecretKeyPacket signKey,
    final SecretSubkeyPacket subkey, {
    final int keyExpirationTime = 0,
    final bool subkeySign = false,
    final DateTime? date,
  }) {
    final subpackets = <SignatureSubpacket>[];
    if (subkeySign) {
      subpackets.add(KeyFlags.fromFlags(KeyFlag.signData.value));
      subpackets.add(EmbeddedSignature.fromSignature(SignaturePacket.createSignature(
        subkey,
        SignatureType.keyBinding,
        Uint8List.fromList([
          ...signKey.writeForSign(),
          ...subkey.writeForSign(),
        ]),
        keyExpirationTime: keyExpirationTime,
        date: date,
      )));
    } else {
      subpackets.add(KeyFlags.fromFlags(KeyFlag.encryptCommunication.value | KeyFlag.encryptStorage.value));
    }
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.subkeyBinding,
      Uint8List.fromList([
        ...signKey.writeForSign(),
        ...subkey.writeForSign(),
      ]),
      subpackets: subpackets,
      preferredHash: _getPreferredHash(subkey),
      keyExpirationTime: keyExpirationTime,
      date: date,
    );
  }

  factory SignaturePacket.createKeyRevocation(
    final SecretKeyPacket signKey, {
    RevocationReasonTag reason = RevocationReasonTag.noReason,
    String description = '',
    final DateTime? date,
  }) {
    return SignaturePacket.createSignature(
      signKey,
      SignatureType.keyRevocation,
      Uint8List.fromList([
        ...signKey.writeForSign(),
      ]),
      subpackets: [RevocationReason.fromRevocation(reason, description)],
      date: date,
    );
  }

  factory SignaturePacket.createLiteralData(
    final SecretKeyPacket signKey,
    final LiteralDataPacket literalData, {
    final String userID = '',
    final DateTime? date,
    final bool detached = false,
  }) {
    return SignaturePacket.createSignature(
      signKey,
      literalData.text.isNotEmpty ? SignatureType.text : SignatureType.binary,
      Uint8List.fromList([
        ...literalData.getBytes(),
      ]),
      subpackets: userID.isNotEmpty ? <SignatureSubpacket>[SignerUserID.fromUserID(userID)] : [],
      date: date,
      attachedHeader: !detached ? literalData.writeHeader() : null,
    );
  }

  @override
  Uint8List toPacketData() => Uint8List.fromList([
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
    final Uint8List? attachedHeader,
  }) {
    if (keyAlgorithm != verifyKey.algorithm) {
      throw ArgumentError('Public key algorithm used to sign signature does not match issuer key algorithm.');
    }
    if (signatureExpirationTime != null &&
        signatureExpirationTime!.expirationTime.compareTo(date ?? DateTime.now()) < 0) {
      /// Signature is expired
      return false;
    }

    final message = Uint8List.fromList([
      ...dataToVerify,
      ...signatureData,
      ..._calculateTrailer(
        signatureType,
        signatureData,
        version,
        attachedHeader: attachedHeader,
      )
    ]);
    final hash = Helper.hashDigest(message, hashAlgorithm);
    if (signedHashValue[0] != hash[0] || signedHashValue[1] != hash[1]) {
      throw Exception('Signed digest did not match');
    }

    switch (keyAlgorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        final publicKey = (verifyKey.publicParams as RSAPublicParams).publicKey;
        return _rsaVerify(publicKey, message);
      case KeyAlgorithm.dsa:
        final publicKey = (verifyKey.publicParams as DSAPublicParams).publicKey;
        return _dsaVerify(publicKey, message);
      case KeyAlgorithm.ecdsa:
        final publicKey = (verifyKey.publicParams as ECPublicParams).publicKey;
        return _ecdsaVerify(publicKey, message);
      case KeyAlgorithm.eddsa:
        throw UnsupportedError('Unsupported public key algorithm for verification.');
      default:
        throw Exception('Unknown public key algorithm for verification.');
    }
  }

  bool verifyUserCertification(
    final KeyPacket verifyKey, {
    UserIDPacket? userID,
    UserAttributePacket? userAttribute,
    final DateTime? date,
  }) {
    final bytes = userID?.toPacketData() ?? userAttribute?.toPacketData();
    if (bytes == null) {
      throw ArgumentError('Either a userID or userAttribute packet needs to be supplied for certification.');
    }
    return verify(
      verifyKey,
      Uint8List.fromList([
        ...verifyKey.writeForSign(),
        (userID != null) ? 0xb4 : 0xd1,
        ...bytes.length.pack32(),
        ...bytes,
      ]),
      date: date,
    );
  }

  static Uint8List _calculateTrailer(
    final SignatureType signatureType,
    final Uint8List signatureData,
    final int version, {
    final Uint8List? attachedHeader,
  }) {
    final List<int> header;
    if (version == 5 && (signatureType == SignatureType.binary || signatureType == SignatureType.text)) {
      header = attachedHeader ?? List.filled(6, 0);
    } else {
      header = [];
    }

    return Uint8List.fromList([
      ...header,
      version,
      0xff,
      ...(version == 5) ? List.filled(4, 0) : <int>[],
      ...signatureData.lengthInBytes.pack32(),
    ]);
  }

  static HashAlgorithm _getPreferredHash(final KeyPacket key) {
    switch (key.algorithm) {
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
        final oid = (key.publicParams as ECPublicParams).oid;
        final curve = CurveInfo.values.firstWhere(
          (info) => info.identifier == oid.objectIdentifierAsString,
          orElse: () => OpenPGP.preferredCurve,
        );
        return curve.hashAlgorithm;
      default:
        return OpenPGP.preferredHashAlgorithm;
    }
  }

  /// Signs provided data. This needs to be done prior to serialization.
  static Uint8List _signMessage(final SecretKeyPacket key, HashAlgorithm hash, final Uint8List message) {
    final Uint8List signature;
    switch (key.algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        final privateKey = (key.secretParams as RSASecretParams).privateKey;
        signature = _rsaSign(privateKey, hash, message);
        break;
      case KeyAlgorithm.dsa:
        final keyParams = key.publicParams as DSAPublicParams;
        final p = keyParams.prime;
        final q = keyParams.order;
        final g = keyParams.generator;
        final x = (key.secretParams as DSASecretParams).secretExponent;
        final privateKey = DSAPrivateKey(x, p, q, g);
        signature = _dsaSign(privateKey, hash, message);
        break;
      case KeyAlgorithm.ecdsa:
        final d = (key.secretParams as ECSecretParams).d;
        final publicKey = (key.publicParams as ECPublicParams).publicKey;
        final privateKey = ECPrivateKey(d, publicKey.parameters);
        signature = _ecdsaSign(privateKey, hash, message);
        break;
      case KeyAlgorithm.eddsa:
        throw UnsupportedError('Unsupported public key algorithm for signing.');
      default:
        throw Exception('Unknown public key algorithm for signing.');
    }
    return signature;
  }

  static Uint8List _rsaSign(final RSAPrivateKey key, HashAlgorithm hash, final Uint8List message) {
    final signer = Signer('${hash.digestName}/RSA')..init(true, PrivateKeyParameter<RSAPrivateKey>(key));
    final signature = signer.generateSignature(message) as RSASignature;
    return Uint8List.fromList([
      ...(signature.bytes.lengthInBytes * 8).pack16(),
      ...signature.bytes,
    ]);
  }

  bool _rsaVerify(final RSAPublicKey key, final Uint8List message) {
    final signer = Signer('${hashAlgorithm.digestName}/RSA')..init(false, PublicKeyParameter<RSAPublicKey>(key));
    final s = Helper.readMPI(signature);
    return signer.verifySignature(message, RSASignature(s.toUnsignedBytes()));
  }

  static Uint8List _dsaSign(final DSAPrivateKey key, HashAlgorithm hash, final Uint8List message) {
    final signer = DSASigner(Digest(hash.digestName))..init(true, PrivateKeyParameter<DSAPrivateKey>(key));
    final signature = signer.generateSignature(message);
    return signature.encode();
  }

  bool _dsaVerify(final DSAPublicKey publicKey, final Uint8List message) {
    final signer = DSASigner(Digest(hashAlgorithm.digestName))
      ..init(false, PublicKeyParameter<DSAPublicKey>(publicKey));

    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return signer.verifySignature(message, DSASignature(r, s));
  }

  static Uint8List _ecdsaSign(final ECPrivateKey key, HashAlgorithm hash, final Uint8List message) {
    final signer = Signer('${hash.digestName}/DET-ECDSA')..init(true, PrivateKeyParameter<ECPrivateKey>(key));
    final signature = signer.generateSignature(message) as ECSignature;
    return Uint8List.fromList([
      ...signature.r.bitLength.pack16(),
      ...signature.r.toUnsignedBytes(),
      ...signature.s.bitLength.pack16(),
      ...signature.s.toUnsignedBytes(),
    ]);
  }

  bool _ecdsaVerify(final ECPublicKey key, final Uint8List message) {
    final signer = Signer('${hashAlgorithm.digestName}/DET-ECDSA')..init(false, PublicKeyParameter<ECPublicKey>(key));

    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return signer.verifySignature(message, ECSignature(r, s));
  }

  /// Creates list of bytes with subpacket data
  static Uint8List _writeSubpackets(final Iterable<SignatureSubpacket> subpackets) {
    final bytes = subpackets.map((subpacket) => subpacket.toSubpacket()).expand((byte) => byte);
    return Uint8List.fromList([...bytes.length.pack16(), ...bytes]);
  }

  /// Reads V4 signature sub packets
  static List<SignatureSubpacket> _readSubpackets(final Uint8List bytes) {
    final subpackets = <SignatureSubpacket>[];
    var offset = 0;
    while (offset < bytes.length) {
      final reader = SubpacketReader.fromSubpacket(bytes, offset);
      offset = reader.end;
      final data = reader.data;
      if (data.isNotEmpty) {
        final critical = ((reader.type & 0x80) != 0);
        final type = SignatureSubpacketType.values.firstWhere((type) => type.value == (reader.type & 0x7f));
        switch (type) {
          case SignatureSubpacketType.signatureCreationTime:
            subpackets.add(SignatureCreationTime(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.signatureExpirationTime:
            subpackets.add(SignatureExpirationTime(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.exportableCertification:
            subpackets.add(ExportableCertification(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.trustSignature:
            subpackets.add(TrustSignature(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.regularExpression:
            subpackets.add(RegularExpression(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.revocable:
            subpackets.add(Revocable(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.keyExpirationTime:
            subpackets.add(KeyExpirationTime(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.preferredSymmetricAlgorithms:
            subpackets.add(PreferredSymmetricAlgorithms(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.revocationKey:
            subpackets.add(RevocationKey(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.issuerKeyID:
            subpackets.add(IssuerKeyID(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.notationData:
            subpackets.add(NotationData(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.preferredHashAlgorithms:
            subpackets.add(PreferredHashAlgorithms(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.preferredCompressionAlgorithms:
            subpackets.add(PreferredCompressionAlgorithms(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.keyServerPreferences:
            subpackets.add(KeyServerPreferences(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.preferredKeyServer:
            subpackets.add(PreferredKeyServer(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.primaryUserID:
            subpackets.add(PrimaryUserID(data, critical: critical));
            break;
          case SignatureSubpacketType.policyURI:
            subpackets.add(PolicyURI(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.keyFlags:
            subpackets.add(KeyFlags(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.signerUserID:
            subpackets.add(SignerUserID(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.revocationReason:
            subpackets.add(RevocationReason(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.features:
            subpackets.add(Features(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.signatureTarget:
            subpackets.add(SignatureTarget(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.embeddedSignature:
            subpackets.add(EmbeddedSignature(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.issuerFingerprint:
            subpackets.add(IssuerFingerprint(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          case SignatureSubpacketType.preferredAEADAlgorithms:
            subpackets.add(PreferredAEADAlgorithms(
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
            break;
          default:
            subpackets.add(SignatureSubpacket(
              type,
              data,
              critical: critical,
              isLongLength: reader.isLongLength,
            ));
        }
      }
    }
    return subpackets;
  }

  static T? _getSubpacket<T extends SignatureSubpacket>(final List<SignatureSubpacket> subpackets) {
    final typedSubpackets = subpackets.whereType<T>();
    return typedSubpackets.isNotEmpty ? typedSubpackets.first : null;
  }
}
