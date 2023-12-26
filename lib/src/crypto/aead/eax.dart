/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import '../../enum/symmetric_algorithm.dart';

import 'base_cipher.dart';

/// EAX Authenticated-Encryption class
class Eax implements BaseCipher {
  final Uint8List _key;

  final EAX _aeadCipher;

  Eax(this._key, final SymmetricAlgorithm symmetric)
      : _aeadCipher = EAX(
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

    return _process(plaintext);
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

    return _process(ciphertext);
  }

  @override
  Uint8List getNonce(
    final Uint8List iv,
    final Uint8List chunkIndex,
  ) {
    final nonce = iv.sublist(0);

    for (var i = 0; i < chunkIndex.length; i++) {
      nonce[8 + i] ^= chunkIndex[i];
    }

    return nonce;
  }

  Uint8List _process(final Uint8List input) {
    final output = Uint8List(
      _aeadCipher.getOutputSize(input.length),
    );
    final len = _aeadCipher.processBytes(
      input,
      0,
      input.length,
      output,
      0,
    );
    final outLen = len + _aeadCipher.doFinal(output, len);
    return Uint8List.view(output.buffer, 0, outLen);
  }
}
