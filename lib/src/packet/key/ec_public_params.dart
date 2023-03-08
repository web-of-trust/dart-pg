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

  final ECPublicKey publicKey;

  ECPublicParams(this.oid, this.q) : publicKey = _publicKeyFromOid(oid, q);

  @override
  Uint8List encode() {
    return Uint8List.fromList([
      ...oid.encode().sublist(1),
      ...q.bitLength.pack16(),
      ...q.toUnsignedBytes(),
    ]);
  }

  static ECPublicKey _publicKeyFromOid(final ASN1ObjectIdentifier oid, final BigInt q) {
    final curve = CurveInfo.values.firstWhere((info) => info.identifierString == oid.objectIdentifierAsString);
    switch (curve) {
      case CurveInfo.ed25519:
      case CurveInfo.curve25519:
        throw UnsupportedError('Curve ${curve.name} is unsupported.');
      default:
        final parameters = ECDomainParameters(curve.name.toLowerCase());
        final point = parameters.curve.decodePoint(q.toUnsignedBytes());
        return ECPublicKey(point, parameters);
    }
  }
}
