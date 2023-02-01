// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'key_params.dart';

class RSASecretParams extends KeyParams {
  final RSAPrivateKey privateKey;

  final BigInt qInv;

  RSASecretParams(this.privateKey, {BigInt? qInv}) : qInv = qInv ?? privateKey.q!.modInverse(privateKey.p!);

  BigInt? get modulus => privateKey.modulus;

  BigInt? get publicExponent => privateKey.publicExponent;

  BigInt? get privateExponent => privateKey.privateExponent;

  BigInt? get primeP => privateKey.p;

  BigInt? get primeQ => privateKey.q;

  factory RSASecretParams.fromPacketData(Uint8List bytes) {
    final privateExponent = KeyParams.readMPI(bytes);

    var pos = privateExponent.byteLength + 2;
    final primeP = KeyParams.readMPI(bytes.sublist(pos));

    pos += primeP.byteLength + 2;
    final primeQ = KeyParams.readMPI(bytes.sublist(pos));

    pos += primeQ.byteLength + 2;
    final qInv = KeyParams.readMPI(bytes.sublist(pos));

    return RSASecretParams(RSAPrivateKey(primeP * primeQ, privateExponent, primeP, primeQ), qInv: qInv);
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...privateExponent!.bitLength.pack16(),
        ...privateExponent!.toUnsignedBytes(),
        ...primeP!.bitLength.pack16(),
        ...primeP!.toUnsignedBytes(),
        ...primeQ!.bitLength.pack16(),
        ...primeQ!.toUnsignedBytes(),
        ...qInv.bitLength.pack16(),
        ...qInv.toUnsignedBytes(),
      ]);
}
