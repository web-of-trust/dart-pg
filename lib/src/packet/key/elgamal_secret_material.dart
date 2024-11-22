/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../common/helpers.dart';
import '../../cryptor/asymmetric/elgamal.dart';
import '../../type/secret_key_material.dart';
import 'elgamal_public_material.dart';

class ElGamalSecretMaterial implements SecretKeyMaterialInterface {
  /// Elgamal secret exponent x.
  final BigInt exponent;

  /// DSA private key
  final ElGamalPrivateKey privateKey;

  @override
  final ElGamalPublicMaterial publicMaterial;

  ElGamalSecretMaterial(this.exponent, this.publicMaterial)
      : privateKey = ElGamalPrivateKey(
          exponent,
          publicMaterial.prime,
          publicMaterial.generator,
        );

  factory ElGamalSecretMaterial.fromBytes(
    final Uint8List bytes,
    ElGamalPublicMaterial publicMaterial,
  ) =>
      ElGamalSecretMaterial(
        Helper.readMPI(bytes),
        publicMaterial,
      );

  @override
  int get keyStrength => publicMaterial.keyStrength;

  @override
  bool get isValid {
    // Check that 1 < g < p
    if (publicMaterial.generator.compareTo(BigInt.one) <= 0 ||
        publicMaterial.generator.compareTo(publicMaterial.prime) >= 0) {
      return false;
    }

    // Expect p-1 to be large
    final pSize = publicMaterial.prime.bitLength;
    if (pSize < 1023) {
      return false;
    }

    // g should have order p-1
    // Check that g ** (p-1) = 1 mod p
    if (publicMaterial.generator
            .modPow(
              publicMaterial.prime - BigInt.one,
              publicMaterial.prime,
            )
            .compareTo(BigInt.one) !=
        0) {
      return false;
    }

    // Re-derive public key y' = g ** x mod p
    // Expect y == y'
    // Blinded exponentiation computes g**{r(p-1) + x} to compare to y
    final r = Helper.randomBigInt(BigInt.two << (pSize - 1), BigInt.two << pSize);
    final rqx = ((publicMaterial.prime - BigInt.one) * r) + exponent;
    return publicMaterial.exponent.compareTo(
          publicMaterial.generator.modPow(rqx, publicMaterial.prime),
        ) ==
        0;
  }

  @override
  Uint8List get toBytes => Uint8List.fromList([
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);
}
