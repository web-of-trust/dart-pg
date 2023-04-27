// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
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

class DSAPublicParams implements VerificationParams {
  /// DSA prime p
  final BigInt prime;

  /// DSA group order q (q is a prime divisor of p-1);
  final BigInt order;

  /// DSA group generator g;
  final BigInt generator;

  /// DSA public-key value y (= g ** x mod p where x is secret).
  final BigInt exponent;

  final DSAPublicKey publicKey;

  DSAPublicParams(
    this.prime,
    this.order,
    this.generator,
    this.exponent,
  ) : publicKey = DSAPublicKey(
          exponent,
          prime,
          order,
          generator,
        );

  factory DSAPublicParams.fromByteData(final Uint8List bytes) {
    final prime = Helper.readMPI(bytes);
    final order = Helper.readMPI(bytes.sublist(prime.byteLength + 2));
    final generator = Helper.readMPI(bytes.sublist(order.byteLength + 2));
    final exponent = Helper.readMPI(bytes.sublist(generator.byteLength + 2));

    return DSAPublicParams(
      prime,
      order,
      generator,
      exponent,
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...prime.bitLength.pack16(),
        ...prime.toUnsignedBytes(),
        ...order.bitLength.pack16(),
        ...order.toUnsignedBytes(),
        ...generator.bitLength.pack16(),
        ...generator.toUnsignedBytes(),
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);

  @override
  Future<bool> verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) async {
    final signer = DSASigner(Digest(hash.digestName))
      ..init(
        false,
        PublicKeyParameter<DSAPublicKey>(publicKey),
      );

    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return signer.verifySignature(message, DSASignature(r, s));
  }
}
