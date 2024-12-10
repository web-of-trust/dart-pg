/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import '../../common/helpers.dart';
import '../../cryptor/asymmetric/dsa.dart';
import '../../enum/hash_algorithm.dart';
import '../../type/signing_key_material.dart';
import 'dsa_public_material.dart';

/// DSA secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class DSASecretMaterial implements SigningKeyMaterialInterface {
  /// DSA secret exponent x
  final BigInt exponent;

  /// DSA private key
  final DSAPrivateKey privateKey;

  @override
  final DSAPublicMaterial publicMaterial;

  DSASecretMaterial(this.exponent, this.publicMaterial)
      : privateKey = DSAPrivateKey(
          exponent,
          publicMaterial.prime,
          publicMaterial.order,
          publicMaterial.generator,
        );

  factory DSASecretMaterial.fromBytes(
    final Uint8List bytes,
    final DSAPublicMaterial publicMaterial,
  ) =>
      DSASecretMaterial(Helper.readMPI(bytes), publicMaterial);

  @override
  get keyStrength => publicMaterial.keyStrength;

  @override
  sign(final Uint8List message, final HashAlgorithm hash) {
    final signer = DSASigner(Digest(hash.digestName))
      ..init(
        true,
        PrivateKeyParameter<DSAPrivateKey>(privateKey),
      );
    return signer.generateSignature(message).encode();
  }

  @override
  get toBytes => Uint8List.fromList([
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);

  @override
  get isValid {
    /// Check that 1 < g < p
    if (publicMaterial.generator.compareTo(BigInt.one) <= 0 ||
        publicMaterial.generator.compareTo(publicMaterial.prime) >= 0) {
      return false;
    }

    /// Check that subgroup order q divides p-1
    if (((publicMaterial.prime - BigInt.one) % publicMaterial.order).sign != 0) {
      return false;
    }

    /// g has order q
    /// Check that g ** q = 1 mod p
    if (publicMaterial.generator
            .modPow(
              publicMaterial.order,
              publicMaterial.prime,
            )
            .compareTo(BigInt.one) !=
        0) {
      return false;
    }

    /// Check q is large
    final qSize = publicMaterial.order.bitLength;
    if (qSize < 150) {
      return false;
    }

    /// Re-derive public key y' = g ** x mod p
    /// Expect y == y'
    /// Blinded exponentiation computes g**{rq + x} to compare to y
    final r = Helper.randomBigInt(
      BigInt.two << (qSize - 1),
      BigInt.two << qSize,
    );
    final rqx = (publicMaterial.order * r) + exponent;
    return publicMaterial.exponent.compareTo(
          publicMaterial.generator.modPow(rqx, publicMaterial.prime),
        ) ==
        0;
  }
}
