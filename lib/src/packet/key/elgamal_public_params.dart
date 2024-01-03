// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../crypto/asymmetric/elgamal.dart';
import '../../helpers.dart';
import 'key_params.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ElGamalPublicParams implements KeyParams {
  /// Elgamal prime p
  final BigInt prime;

  /// Elgamal group generator g
  final BigInt generator;

  /// Elgamal public key value y (= g ** x mod p where x is secret)
  final BigInt exponent;

  final ElGamalPublicKey publicKey;

  ElGamalPublicParams(this.prime, this.generator, this.exponent)
      : publicKey = ElGamalPublicKey(exponent, prime, generator);

  factory ElGamalPublicParams.fromByteData(final Uint8List bytes) {
    final prime = Helper.readMPI(bytes);

    var pos = prime.byteLength + 2;
    final generator = Helper.readMPI(bytes.sublist(pos));

    pos += generator.byteLength + 2;
    final exponent = Helper.readMPI(bytes.sublist(pos));

    return ElGamalPublicParams(prime, generator, exponent);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...prime.bitLength.pack16(),
        ...prime.toUnsignedBytes(),
        ...generator.bitLength.pack16(),
        ...generator.toUnsignedBytes(),
        ...exponent.bitLength.pack16(),
        ...exponent.toUnsignedBytes(),
      ]);
}
