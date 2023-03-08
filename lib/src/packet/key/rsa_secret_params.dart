// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class RSASecretParams extends KeyParams {
  /// RSA secret exponent d
  final BigInt privateExponent;

  /// RSA secret prime value p
  final BigInt primeP;

  /// RSA secret prime value q (p < q)
  final BigInt primeQ;

  /// The multiplicative inverse of p, mod q
  final BigInt pInv;

  final RSAPrivateKey privateKey;

  RSASecretParams(this.privateExponent, this.primeP, this.primeQ, {BigInt? pInv})
      : pInv = pInv ?? primeP.modInverse(primeQ),
        privateKey = RSAPrivateKey(primeP * primeQ, privateExponent, primeP, primeQ);

  /// RSA modulus n
  BigInt get modulus => privateKey.modulus!;

  /// RSA public encryption exponent e
  BigInt get publicExponent => privateKey.publicExponent!;

  factory RSASecretParams.fromPacketData(final Uint8List bytes) {
    final privateExponent = Helper.readMPI(bytes);

    var pos = privateExponent.byteLength + 2;
    final primeP = Helper.readMPI(bytes.sublist(pos));

    pos += primeP.byteLength + 2;
    final primeQ = Helper.readMPI(bytes.sublist(pos));

    pos += primeQ.byteLength + 2;
    final pInv = Helper.readMPI(bytes.sublist(pos));

    return RSASecretParams(privateExponent, primeP, primeQ, pInv: pInv);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...privateExponent.bitLength.pack16(),
        ...privateExponent.toUnsignedBytes(),
        ...primeP.bitLength.pack16(),
        ...primeP.toUnsignedBytes(),
        ...primeQ.bitLength.pack16(),
        ...primeQ.toUnsignedBytes(),
        ...pInv.bitLength.pack16(),
        ...pInv.toUnsignedBytes(),
      ]);

  Uint8List sign(final Uint8List message, final HashAlgorithm hash) {
    final signer = Signer('${hash.digestName}/RSA')..init(true, PrivateKeyParameter<RSAPrivateKey>(privateKey));
    final signature = signer.generateSignature(message) as RSASignature;
    return Uint8List.fromList([
      ...(signature.bytes.lengthInBytes * 8).pack16(),
      ...signature.bytes,
    ]);
  }
}
