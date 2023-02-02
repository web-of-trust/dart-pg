// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/asymmetric/elgamal.dart';
import '../helpers.dart';
import 'key_params.dart';

class ElGamalPublicParams extends KeyParams {
  final ElGamalPublicKey publicKey;

  ElGamalPublicParams(this.publicKey);

  factory ElGamalPublicParams.fromPacketData(Uint8List bytes) {
    final p = KeyParams.readMPI(bytes);

    var pos = p.byteLength + 2;
    final g = KeyParams.readMPI(bytes.sublist(pos));

    pos += g.byteLength + 2;
    final y = KeyParams.readMPI(bytes.sublist(pos));

    return ElGamalPublicParams(ElGamalPublicKey(y, p, g));
  }

  /// Elgamal prime p
  BigInt get primeP => publicKey.p;

  /// Elgamal group generator g
  BigInt get groupGenerator => publicKey.g;

  /// Elgamal public key value y (= g ** x mod p where x is secret)
  BigInt get publicExponent => publicKey.y;

  @override
  Uint8List encode() => Uint8List.fromList([
        ...publicKey.p.bitLength.pack16(),
        ...publicKey.p.toUnsignedBytes(),
        ...publicKey.g.bitLength.pack16(),
        ...publicKey.g.toUnsignedBytes(),
        ...publicKey.y.bitLength.pack16(),
        ...publicKey.y.toUnsignedBytes(),
      ]);
}
