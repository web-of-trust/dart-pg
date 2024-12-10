/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../common/helpers.dart';
import '../../type/key_material.dart';

/// Abstract ec secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class ECSecretMaterial implements KeyMaterialInterface {
  /// ECC's d private parameter
  final BigInt d;

  ECSecretMaterial(this.d);

  @override
  get toBytes => Uint8List.fromList([
        ...d.bitLength.pack16(),
        ...d.toUnsignedBytes(),
      ]);

  static AsymmetricKeyPair generateKeyPair(final String curve) {
    final keyGen = KeyGenerator('EC')
      ..init(
        ParametersWithRandom(
          ECKeyGeneratorParameters(
            ECDomainParameters(curve.toLowerCase()),
          ),
          Helper.secureRandom,
        ),
      );
    return keyGen.generateKeyPair();
  }
}
