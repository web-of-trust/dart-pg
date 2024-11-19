/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import '../enum/hash_algorithm.dart';
import 'key_material.dart';

/// Public key material interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class PublicKeyMaterialInterface extends KeyMaterialInterface {
  /// Verify a signature with message
  bool verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  );
}
