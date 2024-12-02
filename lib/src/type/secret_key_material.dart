/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'key_material.dart';

/// Secret key material interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SecretKeyMaterialInterface implements KeyMaterialInterface {
  /// Get public key material
  KeyMaterialInterface get publicMaterial;

  /// Validate with public key material
  bool get isValid;
}
