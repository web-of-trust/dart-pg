/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../common/extensions.dart';
import '../../enum/ecc.dart';
import '../../type/key_material.dart';

/// Abstract ec public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class ECPublicMaterial implements KeyMaterialInterface {
  /// The curve OID
  final ASN1ObjectIdentifier oid;

  /// Ecc point public key
  final BigInt q;

  /// Ecc curve
  final Ecc curve;

  ECPublicMaterial(this.oid, this.q)
      : curve = Ecc.values.firstWhere(
          (ecc) => ecc.identifierString == oid.objectIdentifierAsString,
        );

  @override
  int get keyLength {
    if (curve == Ecc.ed25519 || curve == Ecc.curve25519) {
      return 255;
    } else {
      final params = ECDomainParameters(curve.name.toLowerCase());
      final key = ECPublicKey(
        params.curve.decodePoint(q.toUnsignedBytes()),
        params,
      );
      return key.Q!.curve.fieldSize;
    }
  }

  @override
  Uint8List get toBytes {
    return Uint8List.fromList([
      ...oid.encode().sublist(1),
      ...q.bitLength.pack16(),
      ...q.toUnsignedBytes(),
    ]);
  }
}
