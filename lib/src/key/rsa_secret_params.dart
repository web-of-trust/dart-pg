// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'key_params.dart';

class RSASecretParams extends KeyParams {
  final RSAPrivateKey privateKey;

  /// The multiplicative inverse of p, mod q
  final BigInt pInv;

  RSASecretParams(this.privateKey, {BigInt? pInv}) : pInv = pInv ?? privateKey.p!.modInverse(privateKey.q!);

  BigInt? get modulus => privateKey.modulus;

  BigInt? get publicExponent => privateKey.publicExponent;

  /// RSA secret exponent d
  BigInt? get privateExponent => privateKey.privateExponent;

  /// RSA secret prime value p
  BigInt? get primeP => privateKey.p;

  /// RSA secret prime value q (p < q)
  BigInt? get primeQ => privateKey.q;

  factory RSASecretParams.fromPacketData(Uint8List bytes) {
    final privateExponent = KeyParams.readMPI(bytes);

    var pos = privateExponent.byteLength + 2;
    final primeP = KeyParams.readMPI(bytes.sublist(pos));

    pos += primeP.byteLength + 2;
    final primeQ = KeyParams.readMPI(bytes.sublist(pos));

    pos += primeQ.byteLength + 2;
    final pInv = KeyParams.readMPI(bytes.sublist(pos));

    return RSASecretParams(RSAPrivateKey(primeP * primeQ, privateExponent, primeP, primeQ), pInv: pInv);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...privateExponent!.bitLength.pack16(),
        ...privateExponent!.toUnsignedBytes(),
        ...primeP!.bitLength.pack16(),
        ...primeP!.toUnsignedBytes(),
        ...primeQ!.bitLength.pack16(),
        ...primeQ!.toUnsignedBytes(),
        ...pInv.bitLength.pack16(),
        ...pInv.toUnsignedBytes(),
      ]);
}
