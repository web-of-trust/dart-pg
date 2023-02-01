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
    final p = KeyParams.readMPI(bytes);

    var pos = p.byteLength + 2;
    final q = KeyParams.readMPI(bytes.sublist(pos));

    pos += q.byteLength + 2;
    final g = KeyParams.readMPI(bytes.sublist(pos));

    pos += g.byteLength + 2;
    final y = KeyParams.readMPI(bytes.sublist(pos));

    return DSAPublicParams(DSAPublicKey(y, p, q, g));
  }

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
