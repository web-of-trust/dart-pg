// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/signer/dsa.dart';
import '../../helpers.dart';
import 'key_params.dart';

class DSAPublicParams extends KeyParams {
  /// DSA prime p
  final BigInt prime;

  /// DSA group order q (q is a prime divisor of p-1);
  final BigInt order;

  /// DSA group generator g;
  final BigInt generator;

  /// DSA public-key value y (= g ** x mod p where x is secret).
  final BigInt publicExponent;

  final DSAPublicKey publicKey;

  DSAPublicParams(this.prime, this.order, this.generator, this.publicExponent)
      : publicKey = DSAPublicKey(publicExponent, prime, order, generator);

  factory DSAPublicParams.fromPacketData(Uint8List bytes) {
    final primeP = Helper.readMPI(bytes);

    var pos = primeP.byteLength + 2;
    final groupOrder = Helper.readMPI(bytes.sublist(pos));

    pos += groupOrder.byteLength + 2;
    final groupGenerator = Helper.readMPI(bytes.sublist(pos));

    pos += groupGenerator.byteLength + 2;
    final publicExponent = Helper.readMPI(bytes.sublist(pos));

    return DSAPublicParams(primeP, groupOrder, groupGenerator, publicExponent);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...prime.bitLength.pack16(),
        ...prime.toUnsignedBytes(),
        ...order.bitLength.pack16(),
        ...order.toUnsignedBytes(),
        ...generator.bitLength.pack16(),
        ...generator.toUnsignedBytes(),
        ...publicExponent.bitLength.pack16(),
        ...publicExponent.toUnsignedBytes(),
      ]);
}
