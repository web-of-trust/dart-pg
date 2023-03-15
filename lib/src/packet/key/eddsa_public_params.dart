// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../helpers.dart';
import 'key_params.dart';

class EdDSAPublicParams extends KeyParams {
  final ASN1ObjectIdentifier oid;

  final BigInt q;

  EdDSAPublicParams(this.oid, this.q);

  factory EdDSAPublicParams.fromByteData(final Uint8List bytes) {
    var pos = 0;
    final length = bytes[pos++];
    if (length == 0 || length == 0xFF) {
      throw UnimplementedError('Future extensions not yet implemented');
    }
    if (length > 127) {
      throw UnsupportedError('Unsupported OID');
    }

    final oid = ASN1ObjectIdentifier.fromBytes(Uint8List.fromList([
      0x06,
      length,
      ...bytes.sublist(pos, pos + length),
    ]));

    pos += length;
    final q = Helper.readMPI(bytes.sublist(pos));
    return EdDSAPublicParams(oid, q);
  }

  @override
  Uint8List encode() {
    return Uint8List.fromList([
      ...oid.encode().sublist(1),
      ...q.bitLength.pack16(),
      ...q.toUnsignedBytes(),
    ]);
  }
}
