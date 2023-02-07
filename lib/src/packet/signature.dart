// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'signature_subpacket.dart';
import 'subpacket_range.dart';

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

  final Revocable? revocable;

  final KeyExpirationTime? keyExpirationTime;

  final PreferredSymmetricAlgorithms? preferredSymmetricAlgorithms;

  final RevocationKey? revocationKey;

  final NotationData? notationData;

  final PreferredHashAlgorithms? preferredHashAlgorithms;

  final PreferredCompressionAlgorithms? preferredCompressionAlgorithms;

  final PrimaryUserID? primaryUserID;

  final KeyFlags? keyFlags;

  final SignerUserID? signerUserID;

  final RevocationReason? revocationReason;

  final Features? features;

  final SignatureTarget? signatureTarget;

  final EmbeddedSignature? embeddedSignature;

  final IssuerFingerprint? issuerFingerprint;

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
    this.revocable,
    this.keyExpirationTime,
    this.preferredSymmetricAlgorithms,
    this.revocationKey,
    this.notationData,
    this.preferredHashAlgorithms,
    this.preferredCompressionAlgorithms,
    this.primaryUserID,
    this.keyFlags,
    this.signerUserID,
    this.revocationReason,
    this.features,
    this.signatureTarget,
    this.embeddedSignature,
    this.issuerFingerprint,
    super.tag = PacketTag.signature,
  });

  bool get signatureNeverExpires => signatureExpirationTime == null;

  bool get keyNeverExpires => keyExpirationTime == null;

  factory SignaturePacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    if (version == 3 || version == 2) {
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
    } else if (version == 4 || version == 5) {
      final signatureType = SignatureType.values.firstWhere((type) => type.value == bytes[pos]);
      pos++;
      final keyAlgorithm = KeyAlgorithm.values.firstWhere((alg) => alg.value == bytes[pos]);
      pos++;
      final hashAlgorithm = HashAlgorithm.values.firstWhere((alg) => alg.value == bytes[pos]);
      pos++;

      final hashedLength = bytes.sublist(pos, pos + 2).toIn16();
      pos += 2;
      final hashedSubpackets = _readSubpackets(bytes.sublist(pos, pos + hashedLength));

      pos += hashedLength;
      final unhashedLength = bytes.sublist(pos, pos + 2).toIn16();
      pos += 2;
      final unhashedSubpackets = _readSubpackets(bytes.sublist(pos, pos + unhashedLength));
      pos += hashedLength;

      final creationTime =
          _getSubpacket<SignatureCreationTime>(hashedSubpackets) ?? SignatureCreationTime.fromTime(DateTime.now());
      final issuerKeyID =
          _getSubpacket<IssuerKeyID>(unhashedSubpackets) ?? _getSubpacket<IssuerKeyID>(hashedSubpackets);
      final issuerFingerprint =
          _getSubpacket<IssuerFingerprint>(unhashedSubpackets) ?? _getSubpacket<IssuerFingerprint>(hashedSubpackets);

      final signedHashValue = bytes.sublist(pos, pos + 2);
      pos += 2;
      final signature = bytes.sublist(pos);

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
    } else {
      throw UnsupportedError('Version $version of the signature packet is unsupported.');
    }
  }

  static List<SignatureSubpacket> _readSubpackets(final Uint8List bytes) {
    final List<SignatureSubpacket> subpackets = [];
    var offset = 0;
    while (offset < bytes.length) {
      final range = SubpacketRange.readSubpacketRange(bytes.sublist(offset));
      offset += range.offset;
      final data = bytes.sublist(offset, offset + range.length);
      offset += range.length;
      if (data.isNotEmpty) {
        final critical = ((data[0] & 0x80) != 0);
        final type = SignatureSubpacketType.values.firstWhere((type) => type.value == (data[0] & 0x7f));
        switch (type) {
          case SignatureSubpacketType.signatureCreationTime:
            subpackets.add(SignatureCreationTime(data, critical: critical));
            break;
          case SignatureSubpacketType.signatureExpirationTime:
            subpackets.add(SignatureExpirationTime(data, critical: critical));
            break;
          case SignatureSubpacketType.exportableCertification:
            subpackets.add(ExportableCertification(data, critical: critical));
            break;
          case SignatureSubpacketType.trustSignature:
            subpackets.add(TrustSignature(data, critical: critical));
            break;
          // case SignatureSubpacketType.regularExpression:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          case SignatureSubpacketType.revocable:
            subpackets.add(Revocable(data, critical: critical));
            break;
          case SignatureSubpacketType.keyExpirationTime:
            subpackets.add(KeyExpirationTime(data, critical: critical));
            break;
          // case SignatureSubpacketType.placeholderBackwardCompatibility:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          case SignatureSubpacketType.preferredSymmetricAlgorithms:
            subpackets.add(PreferredSymmetricAlgorithms(data, critical: critical));
            break;
          case SignatureSubpacketType.revocationKey:
            subpackets.add(RevocationKey(data, critical: critical));
            break;
          case SignatureSubpacketType.issuerKeyID:
            subpackets.add(IssuerKeyID(data, critical: critical));
            break;
          case SignatureSubpacketType.notationData:
            subpackets.add(NotationData(data, critical: critical));
            break;
          case SignatureSubpacketType.preferredHashAlgorithms:
            subpackets.add(PreferredHashAlgorithms(data, critical: critical));
            break;
          case SignatureSubpacketType.preferredCompressionAlgorithms:
            subpackets.add(PreferredCompressionAlgorithms(data, critical: critical));
            break;
          // case SignatureSubpacketType.keyServerPreferences:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          // case SignatureSubpacketType.preferredKeyServer:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          case SignatureSubpacketType.primaryUserID:
            subpackets.add(PrimaryUserID(data, critical: critical));
            break;
          // case SignatureSubpacketType.policyURI:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          case SignatureSubpacketType.keyFlags:
            subpackets.add(KeyFlags(data, critical: critical));
            break;
          case SignatureSubpacketType.signerUserID:
            subpackets.add(SignerUserID(data, critical: critical));
            break;
          case SignatureSubpacketType.revocationReason:
            subpackets.add(RevocationReason(data, critical: critical));
            break;
          case SignatureSubpacketType.features:
            subpackets.add(Features(data, critical: critical));
            break;
          case SignatureSubpacketType.signatureTarget:
            subpackets.add(SignatureTarget(data, critical: critical));
            break;
          case SignatureSubpacketType.embeddedSignature:
            subpackets.add(EmbeddedSignature(data, critical: critical));
            break;
          case SignatureSubpacketType.issuerFingerprint:
            subpackets.add(IssuerFingerprint(data, critical: critical));
            break;
          // case SignatureSubpacketType.preferredAEADAlgorithms:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          // case SignatureSubpacketType.intendedRecipientFingerprint:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          // case SignatureSubpacketType.attestedCertifications:
          //   subpackets.add(SignatureSubpacket(data, critical: critical));
          //   break;
          default:
            subpackets.add(SignatureSubpacket(type, data, critical: critical));
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
    final List<int> bytes = [version];
    if (version == 3 || version == 2) {
      bytes.addAll([5, signatureType.value, ...creationTime.toPacketData(), ...issuerKeyID.toPacketData()]);
      bytes.addAll([keyAlgorithm.value, hashAlgorithm.value]);
    } else if (version == 4 || version == 5) {
      bytes.addAll([signatureType.value, keyAlgorithm.value, hashAlgorithm.value]);

      bytes.addAll(hashedSubpackets.length.pack16());
      for (final packet in hashedSubpackets) {
        bytes.addAll(packet.toPacketData());
      }

      if (unhashedSubpackets.isNotEmpty) {
        bytes.addAll(unhashedSubpackets.length.pack16());
        for (final packet in unhashedSubpackets) {
          bytes.addAll(packet.toPacketData());
        }
      } else {
        bytes.addAll([0, 0]);
      }
    } else {
      throw UnsupportedError('Unknown version $version');
    }

    bytes.addAll(signedHashValue);
    bytes.addAll(signature);
    return Uint8List.fromList(bytes);
  }
}
