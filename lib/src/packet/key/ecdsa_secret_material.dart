/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../common/helpers.dart';
import '../../enum/ecc.dart';
import '../../enum/hash_algorithm.dart';
import '../../type/signing_key_material.dart';
import 'ec_secret_material.dart';
import 'ecdsa_public_material.dart';

/// ECDSA secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class ECDSASecretMaterial extends ECSecretMaterial
    implements SigningKeyMaterialInterface {
  @override
  final ECDSAPublicMaterial publicMaterial;

  ECDSASecretMaterial(super.d, this.publicMaterial);

  factory ECDSASecretMaterial.fromBytes(
    final Uint8List bytes,
    final ECDSAPublicMaterial publicMaterial,
  ) =>
      ECDSASecretMaterial(
        Helper.readMPI(bytes),
        publicMaterial,
      );

  factory ECDSASecretMaterial.generate(final Ecc curve) {
    switch (curve) {
      case Ecc.curve25519:
      case Ecc.ed25519:
        throw UnsupportedError(
          'Curve ${curve.name} is unsupported for ECDSA key generation.',
        );
      default:
        final keyPair = ECSecretMaterial.generateKeyPair(curve.name);
        final privateKey = keyPair.privateKey as ECPrivateKey;
        final q = (keyPair.publicKey as ECPublicKey).Q!;
        return ECDSASecretMaterial(
          privateKey.d!,
          ECDSAPublicMaterial(
            curve.asn1Oid,
            q
                .getEncoded(
                  q.isCompressed,
                )
                .toBigIntWithSign(1),
          ),
        );
    }
  }

  @override
  get isValid {
    final parameters = ECDomainParameters(
      publicMaterial.curve.name.toLowerCase(),
    );
    final q = parameters.curve.decodePoint(
      publicMaterial.q.toUnsignedBytes(),
    );
    return q != null && !q.isInfinity && (parameters.G * d) == q;
  }

  @override
  get keyStrength => publicMaterial.keyStrength;

  @override
  sign(final Uint8List message, final HashAlgorithm hash) {
    final signer = Signer('${hash.digestName}/DET-ECDSA')
      ..init(
        true,
        PrivateKeyParameter<ECPrivateKey>(
          ECPrivateKey(
            d,
            ECDomainParameters(
              publicMaterial.curve.name.toLowerCase(),
            ),
          ),
        ),
      );
    final signature = signer.generateSignature(message) as ECSignature;
    return Uint8List.fromList([
      ...signature.r.bitLength.pack16(),
      ...signature.r.toUnsignedBytes(),
      ...signature.s.bitLength.pack16(),
      ...signature.s.toUnsignedBytes(),
    ]);
  }
}
