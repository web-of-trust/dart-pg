// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/asymmetric/elgamal.dart';
import '../../helpers.dart';
import 'key_params.dart';

class ElGamalPublicParams extends KeyParams {
  /// Elgamal prime p
  final BigInt primeP;

  /// Elgamal group generator g
  final BigInt groupGenerator;

  /// Elgamal public key value y (= g ** x mod p where x is secret)
  final BigInt publicExponent;

  final ElGamalPublicKey publicKey;

  ElGamalPublicParams(this.primeP, this.groupGenerator, this.publicExponent)
      : publicKey = ElGamalPublicKey(publicExponent, primeP, groupGenerator);

  factory ElGamalPublicParams.fromPacketData(Uint8List bytes) {
    final primeP = Helper.readMPI(bytes);

    var pos = primeP.byteLength + 2;
    final groupGenerator = Helper.readMPI(bytes.sublist(pos));

    pos += groupGenerator.byteLength + 2;
    final publicExponent = Helper.readMPI(bytes.sublist(pos));

    return ElGamalPublicParams(primeP, groupGenerator, publicExponent);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...primeP.bitLength.pack16(),
        ...primeP.toUnsignedBytes(),
        ...groupGenerator.bitLength.pack16(),
        ...groupGenerator.toUnsignedBytes(),
        ...publicExponent.bitLength.pack16(),
        ...publicExponent.toUnsignedBytes(),
      ]);
}