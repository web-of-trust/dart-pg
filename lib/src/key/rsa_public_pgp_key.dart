// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'pgp_key.dart';

class RsaPublicPgpKey extends PgpKey {
  final RSAPublicKey publicKey;

  RsaPublicPgpKey(this.publicKey);

  factory RsaPublicPgpKey.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final modulus = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final publicExponent = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    return RsaPublicPgpKey(RSAPublicKey(modulus, publicExponent));
  }

  BigInt? get modulus => publicKey.modulus;

  BigInt? get publicExponent => publicKey.publicExponent;

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(modulus!.bitLength.pack16());
    bytes.addAll(modulus!.toBytes());

    bytes.addAll(publicExponent!.bitLength.pack16());
    bytes.addAll(publicExponent!.toBytes());

    return Uint8List.fromList(bytes);
  }
}
