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
    final p = KeyParams.readMPI(bytes);

    pos += ((p.bitLength + 7) >> 3) + 2;
    final g = KeyParams.readMPI(bytes.sublist(pos));

    pos += ((g.bitLength + 7) >> 3) + 2;
    final y = KeyParams.readMPI(bytes.sublist(pos));

    return ElGamalPublicParams(ElGamalPublicKey(y, p, g));
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(publicKey.p.bitLength.pack16());
    bytes.addAll(publicKey.p.toUnsignedBytes());

    bytes.addAll(publicKey.g.bitLength.pack16());
    bytes.addAll(publicKey.g.toUnsignedBytes());

    bytes.addAll(publicKey.y.bitLength.pack16());
    bytes.addAll(publicKey.y.toUnsignedBytes());

    return Uint8List.fromList(bytes);
  }
}
