/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../type/key_material.dart';
import '../../common/extensions.dart';
import '../../enum/montgomery_curve.dart';

/// Montgomery public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class MontgomeryPublicMaterial implements KeyMaterialInterface {
  final Uint8List publicKey;

  final MontgomeryCurve curve;

  MontgomeryPublicMaterial(this.publicKey, this.curve);

  factory MontgomeryPublicMaterial.fromBytes(
    Uint8List bytes,
    MontgomeryCurve curve,
  ) =>
      MontgomeryPublicMaterial(
        bytes.sublist(0, curve.payloadSize),
        curve,
      );

  @override
  int get keyLength => publicKey.toBigInt().bitLength;

  @override
  Uint8List get toBytes => publicKey;
}
