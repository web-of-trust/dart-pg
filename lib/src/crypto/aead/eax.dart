/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import '../../enum/symmetric_algorithm.dart';

import 'base.dart';

/// EAX Authenticated-Encryption class
class Eax implements Base {
  final Uint8List _key;
  final SymmetricAlgorithm _symmetric;

  Eax(this._key, this._symmetric);

  @override
  Uint8List encrypt(
    final Uint8List plaintext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    final cipher = EAX(
      _symmetric.cipherEngine,
    )..init(
        true,
        AEADParameters(
          KeyParameter(_key),
          _symmetric.blockSize * 8,
          nonce,
          adata,
        ),
      );

    return _process(cipher, plaintext);
  }

  @override
  Uint8List decrypt(
    final Uint8List ciphertext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    final cipher = EAX(
      _symmetric.cipherEngine,
    )..init(
        false,
        AEADParameters(
          KeyParameter(_key),
          _symmetric.blockSize * 8,
          nonce,
          adata,
        ),
      );

    return _process(cipher, ciphertext);
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

  static Uint8List _process(final AEADCipher cipher, final Uint8List input) {
    final output = Uint8List(
      cipher.getOutputSize(input.length),
    );
    final len = cipher.processBytes(
      input,
      0,
      input.length,
      output,
      0,
    );
    final outLen = len + cipher.doFinal(output, len);
    return Uint8List.view(output.buffer, 0, outLen);
  }
}
