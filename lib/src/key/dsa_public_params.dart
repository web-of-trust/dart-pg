// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/signer/dsa.dart';
import '../helpers.dart';
import 'key_params.dart';

class DSAPublicParams extends KeyParams {
  final DSAPublicKey publicKey;

  DSAPublicParams(this.publicKey);

  factory DSAPublicParams.fromPacketData(Uint8List bytes) {
    final primeP = KeyParams.readMPI(bytes);

    var pos = primeP.byteLength + 2;
    final groupOrder = KeyParams.readMPI(bytes.sublist(pos));

    pos += groupOrder.byteLength + 2;
    final groupGenerator = KeyParams.readMPI(bytes.sublist(pos));

    pos += groupGenerator.byteLength + 2;
    final y = KeyParams.readMPI(bytes.sublist(pos));

    return DSAPublicParams(DSAPublicKey(y, primeP, groupOrder, groupGenerator));
  }

  /// DSA prime p
  BigInt get primeP => publicKey.p;

  /// DSA group order q (q is a prime divisor of p-1);
  BigInt get groupOrder => publicKey.q;

  /// DSA group generator g;
  BigInt get groupGenerator => publicKey.g;

  /// DSA public-key value y (= g ** x mod p where x is secret).
  BigInt get publicExponent => publicKey.y;

  @override
  Uint8List encode() => Uint8List.fromList([
        ...publicKey.p.bitLength.pack16(),
        ...publicKey.p.toUnsignedBytes(),
        ...publicKey.q.bitLength.pack16(),
        ...publicKey.q.toUnsignedBytes(),
        ...publicKey.g.bitLength.pack16(),
        ...publicKey.g.toUnsignedBytes(),
        ...publicKey.y.bitLength.pack16(),
        ...publicKey.y.toUnsignedBytes(),
      ]);
}
