// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../../crypto/math/big_int.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/curve_info.dart';
import 'key_params.dart';

abstract class ECPublicParams extends KeyParams {
  final ASN1ObjectIdentifier oid;

  final BigInt q;

  final CurveInfo curve;

  ECPublicParams(this.oid, this.q)
      : curve = CurveInfo.values.firstWhere(
          (info) => info.identifierString == oid.objectIdentifierAsString,
        );

  @override
  Uint8List encode() {
    return Uint8List.fromList([
      ...oid.encode().sublist(1),
      ...q.bitLength.pack16(),
      ...q.toUnsignedBytes(),
    ]);
  }

  static validateOidLength(final int length) {
    if (length == 0 || length == 0xff) {
      throw Exception('Future extensions not yet implemented');
    }
    if (length > 127) {
      throw UnsupportedError('Unsupported OID');
    }
  }
}
