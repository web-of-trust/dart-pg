/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

abstract class Base {
  /// Encrypt plaintext input.
  Uint8List encrypt(
    final Uint8List plaintext,
    final Uint8List nonce,
    final Uint8List adata,
  );

  /// Decrypt ciphertext input.
  Uint8List decrypt(
    final Uint8List ciphertext,
    final Uint8List nonce,
    final Uint8List adata,
  );

  /// Get aead nonce
  Uint8List getNonce(
    final Uint8List iv,
    final Uint8List chunkIndex,
  );
}
