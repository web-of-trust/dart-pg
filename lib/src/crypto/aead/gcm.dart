/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../enum/symmetric_algorithm.dart';
import 'base_cipher.dart';

/// GCM Authenticated-Encryption class
class Gcm implements BaseCipher {
  final Uint8List key;

  final GCMBlockCipher gcmCipher;

  Gcm(this.key, final SymmetricAlgorithm symmetric)
      : gcmCipher = GCMBlockCipher(
          symmetric.cipherEngine,
        );

  @override
  Uint8List decrypt(
    final Uint8List plaintext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    gcmCipher
      ..reset()
      ..init(
        true,
        AEADParameters(KeyParameter(key), gcmCipher.macSize, nonce, adata),
      );
    return gcmCipher.process(plaintext);
  }

  @override
  Uint8List encrypt(
    final Uint8List ciphertext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    gcmCipher
      ..reset()
      ..init(
          false,
          AEADParameters(
            KeyParameter(key),
            gcmCipher.macSize,
            nonce,
            adata,
          ));
    return gcmCipher.process(ciphertext);
  }

  @override
  Uint8List getNonce(
    final Uint8List iv,
    final Uint8List chunkIndex,
  ) {
    final nonce = iv.sublist(0);

    for (var i = 0; i < chunkIndex.length; i++) {
      nonce[4 + i] ^= chunkIndex[i];
    }

    return nonce;
  }
}
