/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import '../../common/helpers.dart';
import '../../cryptor/asymmetric/dsa.dart';
import '../../enum/hash_algorithm.dart';
import '../../type/verification_key_material.dart';

/// DSA public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class DSAPublicMaterial implements VerificationKeyMaterial {
  /// DSA prime p
  final BigInt prime;

  /// DSA group order q (q is a prime divisor of p-1);
  final BigInt order;

  /// DSA group generator g;
  final BigInt generator;

  /// DSA public-key value y (= g ** x mod p where x is secret).
  final BigInt exponent;

  final DSAPublicKey publicKey;

  DSAPublicMaterial(
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

  factory DSAPublicMaterial.fromBytes(final Uint8List bytes) {
    final prime = Helper.readMPI(bytes);

    var pos = prime.byteLength + 2;
    final order = Helper.readMPI(bytes.sublist(pos));

    pos += order.byteLength + 2;
    final generator = Helper.readMPI(bytes.sublist(pos));

    pos += generator.byteLength + 2;
    final exponent = Helper.readMPI(bytes.sublist(pos));

    return DSAPublicMaterial(
      prime,
      order,
      generator,
      exponent,
    );
  }

  @override
  get keyStrength => prime.bitLength;

  @override
  get toBytes => Uint8List.fromList([
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
  verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) {
    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    final signer = DSASigner(Digest(hash.digestName))
      ..init(
        false,
        PublicKeyParameter<DSAPublicKey>(publicKey),
      );
    return signer.verifySignature(message, DSASignature(r, s));
  }
}
