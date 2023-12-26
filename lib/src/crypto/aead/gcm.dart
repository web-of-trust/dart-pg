/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../enum/symmetric_algorithm.dart';
import 'base.dart';

/// GCM Authenticated-Encryption class
class Gcm implements Base {
  final Uint8List _key;

  final GCMBlockCipher _aeadCipher;

  Gcm(this._key, final SymmetricAlgorithm symmetric)
      : _aeadCipher = GCMBlockCipher(
          symmetric.cipherEngine,
        );

  @override
  Uint8List decrypt(
    final Uint8List plaintext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    _aeadCipher
      ..reset()
      ..init(
        true,
        AEADParameters(
          KeyParameter(_key),
          _aeadCipher.macSize,
          nonce,
          adata,
        ),
      );
    return _aeadCipher.process(plaintext);
  }

  @override
  Uint8List encrypt(
    final Uint8List ciphertext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    _aeadCipher
      ..reset()
      ..init(
          false,
          AEADParameters(
          KeyParameter(_key),
          _aeadCipher.macSize,
            nonce,
            adata,
        ),
      );
    return _aeadCipher.process(ciphertext);
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
