// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../helpers.dart';
import 'key_params.dart';

class ElGamalSecretParams implements KeyParams {
  /// Elgamal secret exponent x.
  final BigInt exponent;

  ElGamalSecretParams(this.exponent);

  factory ElGamalSecretParams.fromByteData(final Uint8List bytes) =>
      ElGamalSecretParams(
        Helper.readMPI(bytes),
      );

  @override
  Uint8List encode() => Uint8List.fromList([
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);

  /// Validate ElGamal parameters
  validatePublicParams(final ElGamalPublicParams publicParams) {
    // Check that 1 < g < p
    if (publicParams.generator.compareTo(BigInt.one) <= 0 ||
        publicParams.generator.compareTo(publicParams.prime) >= 0) {
      return false;
    }

    // Expect p-1 to be large
    final pSize = publicParams.prime.bitLength;
    if (pSize < 1023) {
      return false;
    }

    // g should have order p-1
    // Check that g ** (p-1) = 1 mod p
    if (publicParams.generator
            .modPow(publicParams.prime - BigInt.one, publicParams.prime)
            .compareTo(BigInt.one) !=
        0) {
      return false;
    }

    // Since p-1 is not prime, g might have a smaller order that divides p-1
    // We want to make sure that the order is large enough to hinder a small subgroup attack
    // We just check g**i != 1 for all i up to a threshold
    // var res = publicParams.generator;
    // var i = BigInt.one;
    // final threshold = BigInt.two << 17;
    // while (i.compareTo(threshold) < 0) {
    //   res = (res * publicParams.generator).modInverse(publicParams.prime);
    //   if (res.compareTo(BigInt.one) == 0) {
    //     return false;
    //   }
    //   i = i + BigInt.one;
    // }

    // Re-derive public key y' = g ** x mod p
    // Expect y == y'
    // Blinded exponentiation computes g**{r(p-1) + x} to compare to y
    final r =
        Helper.randomBigInt(BigInt.two << (pSize - 1), BigInt.two << pSize);
    final rqx = ((publicParams.prime - BigInt.one) * r) + exponent;
    return publicParams.exponent.compareTo(
            publicParams.generator.modPow(rqx, publicParams.prime)) ==
        0;
  }
}
