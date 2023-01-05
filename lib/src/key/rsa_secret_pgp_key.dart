// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'pgp_key.dart';

class RsaSecretBcpgKey extends PgpKey {
  final RSAPrivateKey privateKey;

  final BigInt qInv;

  RsaSecretBcpgKey(this.privateKey, {BigInt? qInv}) : qInv = qInv ?? privateKey.q!.modInverse(privateKey.p!);

  BigInt? get modulus => privateKey.modulus;

  BigInt? get publicExponent => privateKey.publicExponent;

  BigInt? get privateExponent => privateKey.privateExponent;

  BigInt? get primeP => privateKey.p;

  BigInt? get primeQ => privateKey.q;

  factory RsaSecretBcpgKey.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final privateExponent = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final primeP = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final primeQ = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final qInv = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    return RsaSecretBcpgKey(RSAPrivateKey(primeP * primeQ, privateExponent, primeP, primeQ), qInv: qInv);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(privateExponent!.bitLength.to16Bytes());
    bytes.addAll(privateExponent!.toBytes());

    bytes.addAll(primeP!.bitLength.to16Bytes());
    bytes.addAll(primeP!.toBytes());

    bytes.addAll(primeQ!.bitLength.to16Bytes());
    bytes.addAll(primeQ!.toBytes());

    bytes.addAll(qInv.bitLength.to16Bytes());
    bytes.addAll(qInv.toBytes());

    return Uint8List.fromList(bytes);
  }
}
