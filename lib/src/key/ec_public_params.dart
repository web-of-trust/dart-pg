// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../enums.dart';
import '../helpers.dart';
import 'key_params.dart';

abstract class ECPublicParams extends KeyParams {
  final ECPublicKey publicKey;

  ECPublicParams(this.publicKey);

  @override
  Uint8List encode() {
    final curveName = publicKey.parameters!.domainName.toLowerCase();
    final curveInfo = CurveOid.values.firstWhere((info) => info.name.toLowerCase() == curveName);
    final oid = ASN1ObjectIdentifier(curveInfo.identifier);
    final q = publicKey.Q!.getEncoded(publicKey.Q!.isCompressed).toBigIntWithSign(1);

    return Uint8List.fromList([
      ...oid.encode().sublist(1),
      ...q.bitLength.pack16(),
      ...q.toUnsignedBytes(),
    ]);
  }

  static ECPublicKey publicKeyPacketData(Uint8List bytes) {
    var pos = 0;
    final length = bytes[pos++];
    if (length == 0 || length == 0xFF) {
      throw Exception('Future extensions not yet implemented');
    }
    if (length > 127) {
      throw UnsupportedError('Unsupported OID');
    }

    final derBytes = [0x06, length, ...bytes.sublist(pos, pos + length)];
    final oid = ASN1ObjectIdentifier.fromBytes(Uint8List.fromList(derBytes));

    pos += length;
    final parameters = parametersFromOid(oid);
    final q = Helper.readMPI(bytes.sublist(pos));
    final point = parameters.curve.decodePoint(q.toUnsignedBytes());
    return ECPublicKey(point, parameters);
  }

  static ECDomainParameters parametersFromOid(ASN1ObjectIdentifier oid) {
    final curveOid = CurveOid.values.firstWhere((info) => info.identifierString == oid.objectIdentifierAsString);
    return ECDomainParameters(curveOid.name.toLowerCase());
  }
}
