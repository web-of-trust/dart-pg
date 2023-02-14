// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'key_packet.dart';
import 'signature_subpacket.dart';
import 'subpacket_reader.dart';

/// Signature represents a signature.
/// See RFC 4880, section 5.2.
class SignaturePacket extends ContainedPacket {
  final int version;

  final SignatureType signatureType;

  final KeyAlgorithm keyAlgorithm;

  final HashAlgorithm hashAlgorithm;

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
  });

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
    pos += hashedLength;

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

  bool verify(KeyPacket key, Uint8List data, {bool detached = false}) {
    return false;
  }

  calculateTrailer(Uint8List data, [bool detached = false]) {}

  Uint8List _writeHashedSubpackets() {
    final subpackets = hashedSubpackets.map((subpacket) => subpacket.toSubpacket()).expand((element) => element);
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
  Uint8List toPacketData() => Uint8List.fromList([
        ...signatureData,
        ..._writeUnhashedSubPackets(),
        ...signedHashValue,
        ...signature,
      ]);
}
