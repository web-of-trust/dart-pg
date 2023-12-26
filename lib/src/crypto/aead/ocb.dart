/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../enum/symmetric_algorithm.dart';
import '../modes/ocb_cipher.dart';
import 'base_cipher.dart';

/// OCB Authenticated-Encryption class
class Ocb implements BaseCipher {
  final Uint8List _key;

  final OCBCipher _aeadCipher;

  Ocb(this._key, final SymmetricAlgorithm symmetric)
      : _aeadCipher = OCBCipher(
          symmetric.cipherEngine,
          symmetric.cipherEngine,
        );

  @override
  Uint8List encrypt(
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
  Uint8List decrypt(
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
      nonce[7 + i] ^= chunkIndex[i];
    }

    return nonce;
  }
}
