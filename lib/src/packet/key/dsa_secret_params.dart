// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../crypto/signer/dsa.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class DSASecretParams extends KeyParams {
  /// DSA secret exponent x
  final BigInt exponent;

  DSASecretParams(this.exponent);

  factory DSASecretParams.fromByteData(final Uint8List bytes) =>
      DSASecretParams(
        Helper.readMPI(bytes),
      );

  @override
  Uint8List encode() => Uint8List.fromList([
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);

  Uint8List sign(
    final DSAPublicParams publicParams,
    final Uint8List message,
    final HashAlgorithm hash,
  ) {
    final signer = DSASigner(Digest(hash.digestName))
      ..init(
        true,
        PrivateKeyParameter<DSAPrivateKey>(DSAPrivateKey(
          exponent,
          publicParams.prime,
          publicParams.order,
          publicParams.generator,
        )),
      );
    return signer.generateSignature(message).encode();
  }

  /// Validate DSA parameters
  bool validatePublicParams(final DSAPublicParams publicParams) {
    // Check that 1 < g < p
    if (publicParams.generator.compareTo(BigInt.one) <= 0 ||
        publicParams.generator.compareTo(publicParams.prime) >= 0) {
      return false;
    }

    // Check that subgroup order q divides p-1
    if (((publicParams.prime - BigInt.one) % publicParams.order).sign != 0) {
      return false;
    }

    // g has order q
    // Check that g ** q = 1 mod p
    if (publicParams.generator
            .modPow(publicParams.order, publicParams.prime)
            .compareTo(BigInt.one) !=
        0) {
      return false;
    }

    // Check q is large and probably prime (we mainly want to avoid small factors)
    final qSize = publicParams.order.bitLength;
    if (qSize < 150 || !(publicParams.order.isProbablePrime(32))) {
      return false;
    }

    // Re-derive public key y' = g ** x mod p
    // Expect y == y'
    // Blinded exponentiation computes g**{rq + x} to compare to y
    final r = Helper.randomBigInt(
      BigInt.two << (qSize - 1),
      BigInt.two << qSize,
    );
    final rqx = (publicParams.order * r) + exponent;
    return publicParams.exponent.compareTo(
          publicParams.generator.modPow(rqx, publicParams.prime),
        ) ==
        0;
  }
}
