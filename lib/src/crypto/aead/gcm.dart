/// Copyright 2023-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../enum/symmetric_algorithm.dart';
import 'base.dart';

/// GCM Authenticated-Encryption class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class Gcm implements Base {
  final Uint8List _key;
  final SymmetricAlgorithm _symmetric;

  Gcm(this._key, this._symmetric);

  @override
  Uint8List encrypt(
    final Uint8List ciphertext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    final cipher = GCMBlockCipher(
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
    return cipher.process(ciphertext);
  }

  @override
  Uint8List decrypt(
    final Uint8List plaintext,
    final Uint8List nonce,
    final Uint8List adata,
  ) {
    final cipher = GCMBlockCipher(
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
    return cipher.process(plaintext);
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
