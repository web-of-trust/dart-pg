/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

import 'base_cipher.dart';

/// OCB Authenticated-Encryption class
class Ocb implements BaseCipher {
  @override
  Uint8List decrypt(
    final Uint8List ciphertext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    // TODO: implement decrypt
    throw UnimplementedError();
  }

  @override
  Uint8List encrypt(
    final Uint8List plaintext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    // TODO: implement encrypt
    throw UnimplementedError();
  }

  @override
  Uint8List getNonce(
    final Uint8List iv,
    final Uint8List chunkIndex,
  ) {
    final nonce = iv.sublist(0);

    for (var i = 0; i < chunkIndex.length; i++) {
      nonce[7 + i] ^= chunkIndex[i];
    }

    return nonce;
  }
}
