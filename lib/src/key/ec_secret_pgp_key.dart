// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'pgp_key.dart';

class ECSecretPgpKey extends PgpKey {
  final ECPrivateKey privateKey;

  ECSecretPgpKey(this.privateKey);

  factory ECSecretPgpKey.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var bitLength = bytes.sublist(pos, pos + 2).toIn16();
    pos += 2;
    final d = bytes.sublist(pos, (bitLength + 7) % 8).toBigInt();
    return ECSecretPgpKey(ECPrivateKey(d, null));
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(privateKey.d!.bitLength.to16Bytes());
    bytes.addAll(privateKey.d!.toBytes());

    return Uint8List.fromList(bytes);
  }
}
