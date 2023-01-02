// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../byte_utils.dart';
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
    var bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final privateExponent = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));

    pos += (bitLength + 7) % 8;
    bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final primeP = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));

    pos += (bitLength + 7) % 8;
    bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final primeQ = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));

    pos += (bitLength + 7) % 8;
    bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final qInv = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));

    return RsaSecretBcpgKey(RSAPrivateKey(primeP * primeQ, privateExponent, primeP, primeQ), qInv: qInv);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(ByteUtils.int16Bytes(privateExponent!.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(privateExponent));

    bytes.addAll(ByteUtils.int16Bytes(primeP!.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(primeP));

    bytes.addAll(ByteUtils.int16Bytes(primeQ!.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(primeQ));

    bytes.addAll(ByteUtils.int16Bytes(qInv.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(qInv));

    return Uint8List.fromList(bytes);
  }
}
