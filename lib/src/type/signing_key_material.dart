/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'secret_key_material.dart';
import '../enum/hash_algorithm.dart';

/// Signing key material interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class SigningKeyMaterialInterface extends SecretKeyMaterialInterface {
    /// Sign a message and return signature
  Uint8List sign(
    final Uint8List message,
    final HashAlgorithm hash,
  );
}
