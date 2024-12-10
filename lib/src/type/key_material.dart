/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

/// Key material interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class KeyMaterialInterface {
  /// Get key strength
  int get keyStrength;

  /// Serialize key material to bytes
  Uint8List get toBytes;
}
