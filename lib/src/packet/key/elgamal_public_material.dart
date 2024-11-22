/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../common/helpers.dart';
import '../../cryptor/asymmetric/elgamal.dart';
import '../../type/key_material.dart';

/// ElGamal public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ElGamalPublicMaterial implements KeyMaterialInterface {
  /// Elgamal prime p
  final BigInt prime;

  /// Elgamal group generator g
  final BigInt generator;

  /// Elgamal public key value y (= g ** x mod p where x is secret)
  final BigInt exponent;

  final ElGamalPublicKey publicKey;

  ElGamalPublicMaterial(this.prime, this.generator, this.exponent)
      : publicKey = ElGamalPublicKey(exponent, prime, generator);

  factory ElGamalPublicMaterial.fromBytes(final Uint8List bytes) {
    final prime = Helper.readMPI(bytes);

    var pos = prime.byteLength + 2;
    final generator = Helper.readMPI(bytes.sublist(pos));

    pos += generator.byteLength + 2;
    final exponent = Helper.readMPI(bytes.sublist(pos));

    return ElGamalPublicMaterial(prime, generator, exponent);
  }

  @override
  int get keyStrength => prime.bitLength;

  @override
  Uint8List get toBytes => Uint8List.fromList([
        ...prime.bitLength.pack16(),
        ...prime.toUnsignedBytes(),
        ...generator.bitLength.pack16(),
        ...generator.toUnsignedBytes(),
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);
}
