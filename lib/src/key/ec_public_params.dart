// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../enums.dart';
import '../helpers.dart';
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

  static ECPublicKey _publicKeyFromOid(ASN1ObjectIdentifier oid, BigInt q) {
    final curveOid = CurveOid.values.firstWhere((info) => info.identifierString == oid.objectIdentifierAsString);
    switch (curveOid) {
      case CurveOid.ed25519:
      case CurveOid.curve25519:
        throw UnsupportedError('Unsupported curve.');
      default:
        final parameters = ECDomainParameters(curveOid.name.toLowerCase());
        final point = parameters.curve.decodePoint(q.toUnsignedBytes());
        return ECPublicKey(point, parameters);
    }
  }
}
