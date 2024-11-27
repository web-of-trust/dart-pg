// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class RSASecretParams extends KeyParams {
  /// RSA secret exponent d
  final BigInt exponent;

  /// RSA secret prime value p
  final BigInt primeP;

  /// RSA secret prime value q (p < q)
  final BigInt primeQ;

  /// The multiplicative inverse of p, mod q
  final BigInt coefficient;

  final RSAPrivateKey privateKey;

  RSASecretParams(
    this.exponent,
    this.primeP,
    this.primeQ, {
    BigInt? coefficient,
  })  : coefficient = coefficient ?? primeP.modInverse(primeQ),
        privateKey = RSAPrivateKey(
          primeP * primeQ,
          exponent,
          primeP,
          primeQ,
        );

  /// RSA modulus n
  BigInt get modulus => privateKey.modulus!;

  /// RSA public encryption exponent e
  BigInt get publicExponent => privateKey.publicExponent!;

  factory RSASecretParams.fromByteData(final Uint8List bytes) {
    final privateExponent = Helper.readMPI(bytes);

    var pos = privateExponent.byteLength + 2;
    final primeP = Helper.readMPI(bytes.sublist(pos));

    pos += primeP.byteLength + 2;
    final primeQ = Helper.readMPI(bytes.sublist(pos));

    pos += primeQ.byteLength + 2;
    final coefficient = Helper.readMPI(bytes.sublist(pos));

    return RSASecretParams(
      privateExponent,
      primeP,
      primeQ,
      coefficient: coefficient,
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
        ...primeP.bitLength.pack16(),
        ...primeP.toUnsignedBytes(),
        ...primeQ.bitLength.pack16(),
        ...primeQ.toUnsignedBytes(),
        ...coefficient.bitLength.pack16(),
        ...coefficient.toUnsignedBytes(),
      ]);

  Uint8List sign(
    final Uint8List message,
    final HashAlgorithm hash,
  ) {
    final signer = Signer('${hash.digestName}/RSA')
      ..init(
        true,
        PrivateKeyParameter<RSAPrivateKey>(privateKey),
      );
    final signature = signer.generateSignature(message) as RSASignature;
    return Uint8List.fromList([
      ...(signature.bytes.length * 8).pack16(),
      ...signature.bytes,
    ]);
  }

  /// Validate RSA parameters
  bool validatePublicParams(final RSAPublicParams publicParams) {
    // expect pq = n
    if ((primeP * primeQ).compareTo(publicParams.modulus) != 0) {
      return false;
    }
    // expect p*u = 1 mod q
    if (((primeP * coefficient) % primeQ).compareTo(BigInt.one) != 0) {
      return false;
    }

    final nSizeOver3 = (publicParams.modulus.bitLength / 3).floor();
    final r = Helper.randomBigInt(BigInt.two, BigInt.two << nSizeOver3);
    final rde = r * exponent * publicParams.exponent;
    return (rde % (primeP - BigInt.one)).compareTo(r) == 0 &&
        (rde % (primeQ - BigInt.one)).compareTo(r) == 0;
  }
}
