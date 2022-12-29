// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../byte_utils.dart';
import 'pgp_key.dart';

class ECSecretPgpKey extends PgpKey {
  final ECPrivateKey privateKey;

  ECSecretPgpKey(this.privateKey);

  factory ECSecretPgpKey.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final d = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));
    return ECSecretPgpKey(ECPrivateKey(d, null));
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(ByteUtils.int16Bytes(privateKey.d!.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(privateKey.d));

    return Uint8List.fromList(bytes);
  }
}
