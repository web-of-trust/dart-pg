/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:pinenacl/tweetnacl.dart';

import '../../common/helpers.dart';
import '../../enum/ecc.dart';
import '../../enum/hash_algorithm.dart';
import '../../type/signing_key_material.dart';
import 'eddsa_legacy_public_material.dart';

/// EdDSA legacy secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class EdDSALegacySecretMaterial implements SigningKeyMaterialInterface {
  /// Ed's seed parameter
  final BigInt seed;

  @override
  final EdDSALegacyPublicMaterial publicMaterial;

  EdDSALegacySecretMaterial(this.seed, this.publicMaterial);

  factory EdDSALegacySecretMaterial.fromBytes(
    final Uint8List bytes,
    final EdDSALegacyPublicMaterial publicMaterial,
  ) =>
      EdDSALegacySecretMaterial(
        Helper.readMPI(bytes),
        publicMaterial,
      );

  factory EdDSALegacySecretMaterial.generate() {
    final seed = Helper.randomBytes(TweetNaCl.seedSize);
    return EdDSALegacySecretMaterial(
      seed.toBigIntWithSign(1),
      EdDSALegacyPublicMaterial(
          Ecc.ed25519.asn1Oid,
          Uint8List.fromList([
            0x40,
            ...nacl.SigningKey.fromSeed(seed).verifyKey.asTypedList,
          ]).toBigIntWithSign(1)),
    );
  }

  @override
  bool get isValid {
    final signingKey = nacl.SigningKey.fromSeed(seed.toUnsignedBytes());
    final dG = Uint8List.fromList([
      0x40,
      ...signingKey.verifyKey.asTypedList,
    ]);
    return publicMaterial.q.compareTo(dG.toBigIntWithSign(1)) == 0;
  }

  @override
  int get keyStrength => publicMaterial.keyStrength;

  @override
  Uint8List sign(Uint8List message, HashAlgorithm hash) {
    final signed = nacl.SigningKey.fromSeed(seed.toUnsignedBytes()).sign(
      Helper.hashDigest(message, hash),
    );
    final bitLength = (nacl.SignedMessage.signatureLength * 4).pack16();
    return Uint8List.fromList([
      ...bitLength, // r bit length
      ...signed.signature.sublist(0, nacl.SignedMessage.signatureLength ~/ 2), // r
      ...bitLength, // s bit length
      ...signed.signature.sublist(nacl.SignedMessage.signatureLength ~/ 2), // s
    ]);
  }

  @override
  Uint8List get toBytes => Uint8List.fromList([
        ...seed.bitLength.pack16(),
        ...seed.toUnsignedBytes(),
      ]);
}
