// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../byte_utils.dart';
import 'pgp_key.dart';

class ElGamalPublicPgpKey extends PgpKey {
  final BigInt p;
  final BigInt g;
  final BigInt y;

  ElGamalPublicPgpKey(this.p, this.g, this.y);

  factory ElGamalPublicPgpKey.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final p = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));

    pos += (bitLength + 7) % 8;
    bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final g = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));

    pos += (bitLength + 7) % 8;
    bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final y = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));

    return ElGamalPublicPgpKey(p, g, y);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(ByteUtils.int16Bytes(p.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(p));

    bytes.addAll(ByteUtils.int16Bytes(g.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(g));

    bytes.addAll(ByteUtils.int16Bytes(y.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(y));

    return Uint8List.fromList(bytes);
  }
}
