// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'key_packet.dart';
import 'signature/key_server_preferences.dart';
import 'signature/policy_uri.dart';
import 'signature/preferred_aead_algorithms.dart';
import 'signature/preferred_key_server.dart';
import 'signature/regular_expression.dart';
import 'signature_subpacket.dart';
import 'subpacket_reader.dart';

/// Signature represents a signature.
/// See RFC 4880, section 5.2.
class SignaturePacket extends ContainedPacket {
  final int version;

  final SignatureType signatureType;

  final KeyAlgorithm keyAlgorithm;

  final HashAlgorithm hashAlgorithm;

  final SignatureCreationTime creationTime;

  final IssuerKeyID issuerKeyID;

  final Uint8List signedHashValue;

  final Uint8List signature;

  final List<SignatureSubpacket> hashedSubpackets;

  final List<SignatureSubpacket> unhashedSubpackets;

  final SignatureExpirationTime? signatureExpirationTime;

  final ExportableCertification? exportable;

  final TrustSignature? trustSignature;

  final RegularExpression? regularExpression;

  final Revocable? revocable;

  final KeyExpirationTime? keyExpirationTime;

  final PreferredSymmetricAlgorithms? preferredSymmetricAlgorithms;

  final RevocationKey? revocationKey;

  final NotationData? notationData;

  final PreferredHashAlgorithms? preferredHashAlgorithms;

  final PreferredCompressionAlgorithms? preferredCompressionAlgorithms;

  final KeyServerPreferences? keyServerPreferences;

  final PreferredKeyServer? preferredKeyServer;

  final PrimaryUserID? primaryUserID;

  final PolicyURI? policyURI;

  final KeyFlags? keyFlags;

  final SignerUserID? signerUserID;

  final RevocationReason? revocationReason;

  final Features? features;

  final SignatureTarget? signatureTarget;

  final EmbeddedSignature? embeddedSignature;

  final IssuerFingerprint? issuerFingerprint;

  final PreferredAEADAlgorithms? preferredAEADAlgorithms;

  SignaturePacket(
    this.version,
    this.signatureType,
    this.keyAlgorithm,
    this.hashAlgorithm,
    this.creationTime,
    this.issuerKeyID,
    this.signedHashValue,
    this.signature, {
    this.hashedSubpackets = const [],
    this.unhashedSubpackets = const [],
    this.signatureExpirationTime,
    this.exportable,
    this.trustSignature,
    this.regularExpression,
    this.revocable,
    this.keyExpirationTime,
    this.preferredSymmetricAlgorithms,
    this.revocationKey,
    this.notationData,
    this.preferredHashAlgorithms,
    this.preferredCompressionAlgorithms,
    this.keyServerPreferences,
    this.preferredKeyServer,
    this.primaryUserID,
    this.policyURI,
    this.keyFlags,
    this.signerUserID,
    this.revocationReason,
    this.features,
    this.signatureTarget,
    this.embeddedSignature,
    this.issuerFingerprint,
    this.preferredAEADAlgorithms,
    super.tag = PacketTag.signature,
  });

  bool get signatureNeverExpires => signatureExpirationTime == null;

  bool get keyNeverExpires => keyExpirationTime == null;

  Uint8List get signatureData {
    return Uint8List.fromList([
      version,
      signatureType.value,
      keyAlgorithm.value,
      hashAlgorithm.value,
      ..._writeHashedSubpackets(),
    ]);
  }

  factory SignaturePacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    switch (version) {
      case 2:
      case 3:
        pos++;

        /// One-octet signature type.
        final signatureType = SignatureType.values.firstWhere((type) => type.value == bytes[pos]);
        pos++;

        /// Four-octet creation time.
        final creationTime = SignatureCreationTime.fromTime(bytes.sublist(pos, pos + 4).toDateTime());
        pos += 4;

        /// Eight-octet Key ID of signer.
        final issuerKeyID = IssuerKeyID.fromKeyID(bytes.sublist(pos, pos + 8).toHexadecimal());
        pos += 8;

        /// One-octet public-key algorithm.
        final keyAlgorithm = KeyAlgorithm.values.firstWhere((alg) => alg.value == bytes[pos]);
        pos++;

        /// One-octet hash algorithm.
        final hashAlgorithm = HashAlgorithm.values.firstWhere((alg) => alg.value == bytes[pos]);
        pos++;

        /// Two-octet field holding left 16 bits of signed hash value.
        final signedHashValue = bytes.sublist(pos, pos + 2);
        pos += 2;
        final signature = bytes.sublist(pos);

        return SignaturePacket(
          version,
          signatureType,
          keyAlgorithm,
          hashAlgorithm,
          creationTime,
          issuerKeyID,
          signedHashValue,
          signature,
        );
      case 4:
      case 5:

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
        pos += hashedLength;

        /// Two-octet field holding left 16 bits of signed hash value.
        final signedHashValue = bytes.sublist(pos, pos + 2);
        pos += 2;
        final signature = bytes.sublist(pos);

        final creationTime =
            _getSubpacket<SignatureCreationTime>(hashedSubpackets) ?? SignatureCreationTime.fromTime(DateTime.now());
        final issuerKeyID =
            _getSubpacket<IssuerKeyID>(hashedSubpackets) ?? _getSubpacket<IssuerKeyID>(unhashedSubpackets);
        final issuerFingerprint =
            _getSubpacket<IssuerFingerprint>(hashedSubpackets) ?? _getSubpacket<IssuerFingerprint>(unhashedSubpackets);

        return SignaturePacket(
          version,
          signatureType,
          keyAlgorithm,
          hashAlgorithm,
          creationTime,
          issuerKeyID ?? IssuerKeyID(issuerFingerprint?.fingerprint.hexToBytes() ?? Uint8List.fromList([0])),
          signedHashValue,
          signature,
          hashedSubpackets: hashedSubpackets,
          unhashedSubpackets: unhashedSubpackets,
          signatureExpirationTime: _getSubpacket<SignatureExpirationTime>(hashedSubpackets),
          exportable: _getSubpacket<ExportableCertification>(hashedSubpackets),
          trustSignature: _getSubpacket<TrustSignature>(hashedSubpackets),
          revocable: _getSubpacket<Revocable>(hashedSubpackets),
          keyExpirationTime: _getSubpacket<KeyExpirationTime>(hashedSubpackets),
          preferredSymmetricAlgorithms: _getSubpacket<PreferredSymmetricAlgorithms>(hashedSubpackets),
          revocationKey: _getSubpacket<RevocationKey>(hashedSubpackets),
          notationData: _getSubpacket<NotationData>(hashedSubpackets),
          preferredHashAlgorithms: _getSubpacket<PreferredHashAlgorithms>(hashedSubpackets),
          preferredCompressionAlgorithms: _getSubpacket<PreferredCompressionAlgorithms>(hashedSubpackets),
          primaryUserID: _getSubpacket<PrimaryUserID>(hashedSubpackets),
          keyFlags: _getSubpacket<KeyFlags>(hashedSubpackets),
          signerUserID: _getSubpacket<SignerUserID>(hashedSubpackets),
          revocationReason: _getSubpacket<RevocationReason>(hashedSubpackets),
          features: _getSubpacket<Features>(hashedSubpackets),
          signatureTarget: _getSubpacket<SignatureTarget>(hashedSubpackets),
          embeddedSignature: _getSubpacket<EmbeddedSignature>(hashedSubpackets),
          issuerFingerprint: issuerFingerprint,
        );
      default:
        throw UnsupportedError('Version $version of the signature packet is unsupported.');
    }
  }

  bool verify(KeyPacket key, Uint8List data, {bool detached = false}) {
    return false;
  }

  calculateTrailer(Uint8List data, [bool detached = false]) {}

  Uint8List _writeHashedSubpackets() {
    final subpackets = hashedSubpackets.isEmpty
        ? <int>[
            ...creationTime.toSubpacket(),
            ...signatureExpirationTime?.toSubpacket() ?? [],
            ...exportable?.toSubpacket() ?? [],
            ...trustSignature?.toSubpacket() ?? [],
            ...regularExpression?.toSubpacket() ?? [],
            ...revocable?.toSubpacket() ?? [],
            ...keyExpirationTime?.toSubpacket() ?? [],
            ...preferredSymmetricAlgorithms?.toSubpacket() ?? [],
            ...revocationKey?.toSubpacket() ?? [],
            ...issuerKeyID.toSubpacket(),
            ...notationData?.toSubpacket() ?? [],
            ...preferredHashAlgorithms?.toSubpacket() ?? [],
            ...preferredCompressionAlgorithms?.toSubpacket() ?? [],
            ...keyServerPreferences?.toSubpacket() ?? [],
            ...preferredKeyServer?.toSubpacket() ?? [],
            ...primaryUserID?.toSubpacket() ?? [],
            ...policyURI?.toSubpacket() ?? [],
            ...keyFlags?.toSubpacket() ?? [],
            ...signerUserID?.toSubpacket() ?? [],
            ...revocationReason?.toSubpacket() ?? [],
            ...features?.toSubpacket() ?? [],
            ...signatureTarget?.toSubpacket() ?? [],
            ...embeddedSignature?.toSubpacket() ?? [],
            ...issuerFingerprint?.toSubpacket() ?? [],
            ...preferredAEADAlgorithms?.toSubpacket() ?? [],
          ]
        : hashedSubpackets.map((subpacket) => subpacket.toSubpacket()).expand((element) => element);
    return Uint8List.fromList([...subpackets.length.pack16(), ...subpackets]);
  }

  Uint8List _writeUnhashedSubPackets() {
    final subpackets = unhashedSubpackets.isEmpty
        ? [0, 0]
        : unhashedSubpackets.map((subpacket) => subpacket.toSubpacket()).expand((element) => element);
    return Uint8List.fromList([...subpackets.length.pack16(), ...subpackets]);
  }

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

  static T? _getSubpacket<T extends SignatureSubpacket>(List<SignatureSubpacket> subpackets) {
    final typedSubpackets = subpackets.whereType<T>();
    return typedSubpackets.isNotEmpty ? typedSubpackets.first : null;
  }

  @override
  Uint8List toPacketData() {
    switch (version) {
      case 2:
      case 3:
        return Uint8List.fromList([
          version,
          5,
          signatureType.value,
          ...creationTime.toSubpacket(),
          ...issuerKeyID.toSubpacket(),
          keyAlgorithm.value,
          hashAlgorithm.value,
          ...signedHashValue,
          ...signature,
        ]);
      case 4:
      case 5:
        return Uint8List.fromList([
          ...signatureData,
          ..._writeUnhashedSubPackets(),
          ...signedHashValue,
          ...signature,
        ]);
      default:
        throw UnsupportedError('Unknown version $version');
    }
  }
}
