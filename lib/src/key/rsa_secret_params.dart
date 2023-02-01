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
    var pos = 0;
    final privateExponent = KeyParams.readMPI(bytes);

    pos += ((privateExponent.bitLength + 7) >> 3) + 2;
    final primeP = KeyParams.readMPI(bytes.sublist(pos));

    pos += ((primeP.bitLength + 7) >> 3) + 2;
    final primeQ = KeyParams.readMPI(bytes.sublist(pos));

    pos += ((primeQ.bitLength + 7) >> 3) + 2;
    final qInv = KeyParams.readMPI(bytes.sublist(pos));

    return RSASecretParams(RSAPrivateKey(primeP * primeQ, privateExponent, primeP, primeQ), qInv: qInv);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(privateExponent!.bitLength.pack16());
    bytes.addAll(privateExponent!.toUnsignedBytes());

    bytes.addAll(primeP!.bitLength.pack16());
    bytes.addAll(primeP!.toUnsignedBytes());

    bytes.addAll(primeQ!.bitLength.pack16());
    bytes.addAll(primeQ!.toUnsignedBytes());

    bytes.addAll(qInv.bitLength.pack16());
    bytes.addAll(qInv.toUnsignedBytes());

    return Uint8List.fromList(bytes);
  }
}
