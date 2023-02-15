// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../openpgp.dart';
import 'literal_data.dart';
import 'secret_key.dart';
import 'secret_subkey.dart';
import 'signature_packet.dart';
import 'signature_subpacket.dart';
import 'user_id.dart';

class SignatureGenerator {
  static createCleartextSignature(LiteralDataPacket data) {}

  static SignaturePacket createBindingSignature(
    SecretSubkeyPacket subkey,
    SecretKeyPacket primaryKey, {
    CurveOid curve = OpenPGP.preferredEcCurve,
    DateTime? date,
  }) {
    final HashAlgorithm preferredHashAlgo;
    switch (subkey.algorithm) {
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
        preferredHashAlgo = curve.hashAlgorithm;
        break;
      default:
        preferredHashAlgo = OpenPGP.preferredHashAlgorithm;
    }

    return SignaturePacket(
      4,
      SignatureType.subkeyBinding,
      primaryKey.algorithm,
      preferredHashAlgo,
      Uint8List(0),
      Uint8List(0),
    ).sign(
      primaryKey,
      keyData: primaryKey,
      bindKeyData: subkey,
      date: date,
    );
  }

  static SignaturePacket createCertGenericSignature(
    UserIDPacket userID,
    SecretKeyPacket secretKey, {
    CurveOid curve = OpenPGP.preferredEcCurve,
    DateTime? date,
  }) {
    final HashAlgorithm preferredHashAlgo;
    switch (secretKey.algorithm) {
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
        preferredHashAlgo = curve.hashAlgorithm;
        break;
      default:
        preferredHashAlgo = OpenPGP.preferredHashAlgorithm;
    }
    return SignaturePacket(
      4,
      SignatureType.certGeneric,
      secretKey.algorithm,
      preferredHashAlgo,
      Uint8List(0),
      Uint8List(0),
      hashedSubpackets: [
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
    ).sign(
      secretKey,
      userID: userID,
      keyData: secretKey,
      date: date,
    );
  }
}
