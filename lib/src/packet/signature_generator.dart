// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../openpgp.dart';
import 'key/key_params.dart';
import 'key_packet.dart';
import 'signature_packet.dart';
import 'signature_subpacket.dart';
import 'user_id.dart';

class SignatureGenerator {
  static SignaturePacket createRevocationSignature(
    SecretKeyPacket secretKey, {
    DateTime? date,
  }) {
    return SignaturePacket(
      secretKey.version,
      SignatureType.keyRevocation,
      secretKey.algorithm,
      _getPreferredHashAlgo(secretKey),
      Uint8List(0),
      Uint8List(0),
      hashedSubpackets: [RevocationReason.fromRevocation(RevocationReasonTag.noReason, '')],
    ).sign(
      secretKey,
      keyData: secretKey,
      date: date,
    );
  }

  static SignaturePacket createBindingSignature(
    SecretSubkeyPacket subkey,
    SecretKeyPacket primaryKey, {
    int keyExpirationTime = 0,
    bool subkeySign = false,
    DateTime? date,
  }) {
    final preferredHashAlgo = _getPreferredHashAlgo(subkey);
    final hashedSubpackets = <SignatureSubpacket>[];
    if (subkeySign) {
      hashedSubpackets.add(KeyFlags.fromFlags(KeyFlag.signData.value));
      final embeddedSignature = SignaturePacket(
        subkey.version,
        SignatureType.keyBinding,
        subkey.algorithm,
        preferredHashAlgo,
        Uint8List(0),
        Uint8List(0),
        hashedSubpackets: [],
      ).sign(
        subkey,
        keyData: primaryKey,
        bindKeyData: subkey,
        date: date,
      );
      hashedSubpackets.add(EmbeddedSignature(embeddedSignature.toPacketData()));
    } else {
      hashedSubpackets.add(KeyFlags.fromFlags(KeyFlag.encryptCommunication.value | KeyFlag.encryptStorage.value));
    }
    if (keyExpirationTime > 0) {
      hashedSubpackets.add(KeyExpirationTime.fromTime(keyExpirationTime));
    }

    return SignaturePacket(
      primaryKey.version,
      SignatureType.subkeyBinding,
      primaryKey.algorithm,
      preferredHashAlgo,
      Uint8List(0),
      Uint8List(0),
      hashedSubpackets: hashedSubpackets,
    ).sign(
      primaryKey,
      keyData: primaryKey,
      bindKeyData: subkey,
      date: date,
    );
  }

  static SignaturePacket createCertificateSignature(
    UserIDPacket userID,
    SecretKeyPacket secretKey, {
    int keyExpirationTime = 0,
    DateTime? date,
  }) {
    final hashedSubpackets = [
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
    ];
    if (keyExpirationTime > 0) {
      hashedSubpackets.add(KeyExpirationTime.fromTime(keyExpirationTime));
    }

    return SignaturePacket(
      secretKey.version,
      SignatureType.certGeneric,
      secretKey.algorithm,
      _getPreferredHashAlgo(secretKey),
      Uint8List(0),
      Uint8List(0),
      hashedSubpackets: hashedSubpackets,
    ).sign(
      secretKey,
      userID: userID,
      keyData: secretKey,
      date: date,
    );
  }

  static HashAlgorithm _getPreferredHashAlgo(KeyPacket keyPacket) {
    switch (keyPacket.algorithm) {
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
        final oid = (keyPacket.publicParams as ECPublicParams).oid;
        final curve = CurveInfo.values.firstWhere(
          (info) => info.identifierString == oid.objectIdentifierAsString,
          orElse: () => OpenPGP.preferredCurve,
        );
        return curve.hashAlgorithm;
      default:
        return OpenPGP.preferredHashAlgorithm;
    }
  }
}
