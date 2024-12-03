/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'secret_key_material.dart';

/// Session key cryptor interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SessionKeyCryptorInterface {
  /// Serialize session key cryptor to bytes
  Uint8List encode();

  /// Decrypt session key by using secret key packet
  Uint8List decrypt(SecretKeyMaterialInterface key);
}
