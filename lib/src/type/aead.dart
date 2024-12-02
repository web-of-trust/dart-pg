/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

/// AEAD Authenticated-Encryption interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class AeadInterface {
  /// Encrypt plaintext input.
  Uint8List encrypt(
    final Uint8List plainText,
    final Uint8List nonce,
    final Uint8List aData,
  );

  /// Decrypt ciphertext input.
  Uint8List decrypt(
    final Uint8List cipherText,
    final Uint8List nonce,
    final Uint8List aData,
  );

  /// Get aead nonce
  Uint8List getNonce(
    final Uint8List iv,
    final Uint8List chunkIndex,
  );
}
