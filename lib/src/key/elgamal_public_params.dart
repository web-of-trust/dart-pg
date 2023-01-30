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
    var pos = 0;
    var bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final p = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final g = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final y = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    return ElGamalPublicParams(ElGamalPublicKey(y, p, g));
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(publicKey.p.bitLength.pack16());
    bytes.addAll(publicKey.p.toBytes());

    bytes.addAll(publicKey.g.bitLength.pack16());
    bytes.addAll(publicKey.g.toBytes());

    bytes.addAll(publicKey.y.bitLength.pack16());
    bytes.addAll(publicKey.y.toBytes());

    return Uint8List.fromList(bytes);
  }
}
