// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../byte_utils.dart';
import 'pgp_key.dart';

class RsaSecretBcpgKey extends PgpKey {
  final RSAPrivateKey privateKey;

  RsaSecretBcpgKey(this.privateKey);

  BigInt? get modulus => privateKey.modulus;

  BigInt? get publicExponent => privateKey.publicExponent;

  BigInt? get privateExponent => privateKey.privateExponent;

  BigInt? get primeP => privateKey.p;

  BigInt? get primeQ => privateKey.q;

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(ByteUtils.int16Bytes(privateExponent!.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(privateExponent));

    bytes.addAll(ByteUtils.int16Bytes(primeP!.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(primeP));

    bytes.addAll(ByteUtils.int16Bytes(primeQ!.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(primeQ));

    final qInv = primeQ!.modInverse(primeP!);
    bytes.addAll(ByteUtils.int16Bytes(qInv.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(qInv));

    return Uint8List.fromList(bytes);
  }
}
