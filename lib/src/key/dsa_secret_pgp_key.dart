// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../byte_utils.dart';
import 'pgp_key.dart';

class DsaSecretPgpKey extends PgpKey {
  final BigInt x;

  DsaSecretPgpKey(this.x);

  factory DsaSecretPgpKey.fromPacketData(Uint8List bytes) {
    var pos = 0;
    var bitLength = ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2));
    pos += 2;
    final x = ByteUtils.bytesToBigInt(bytes.sublist(pos, (bitLength + 7) % 8));
    return DsaSecretPgpKey(x);
  }

  @override
  Uint8List encode() {
    final List<int> bytes = [];

    bytes.addAll(ByteUtils.int16Bytes(x.bitLength));
    bytes.addAll(ByteUtils.bigIntBytes(x));

    return Uint8List.fromList(bytes);
  }
}
