// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../helpers.dart';
import 'pgp_key.dart';

class DsaPublicPgpKey extends PgpKey {
  final BigInt p;
  final BigInt q;
  final BigInt g;
  final BigInt y;

  DsaPublicPgpKey(this.p, this.q, this.g, this.y);

  factory DsaPublicPgpKey.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final p = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final q = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final g = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    pos += (bitLength + 7) % 8;
    bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final y = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();

    return DsaPublicPgpKey(p, q, g, y);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(p.bitLength.pack16());
    bytes.addAll(p.toBytes());

    bytes.addAll(q.bitLength.pack16());
    bytes.addAll(q.toBytes());

    bytes.addAll(g.bitLength.pack16());
    bytes.addAll(g.toBytes());

    bytes.addAll(y.bitLength.pack16());
    bytes.addAll(y.toBytes());

    return Uint8List.fromList(bytes);
  }
}
