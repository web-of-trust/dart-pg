/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../enum/symmetric_algorithm.dart';
import '../../type/aead.dart';

/// GCM Authenticated-Encryption class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class Gcm implements AeadInterface {
  final Uint8List key;
  final SymmetricAlgorithm symmetric;

  Gcm(this.key, this.symmetric);

  @override
  encrypt(
    final Uint8List plainText,
    final Uint8List nonce,
    final Uint8List aData,
  ) {
    final cipher = GCMBlockCipher(
      symmetric.cipherEngine,
    )..init(
        true,
        AEADParameters(
          KeyParameter(key),
          symmetric.blockSize * 8,
          nonce,
          aData,
        ),
      );
    return cipher.process(plainText);
  }

  @override
  decrypt(
    final Uint8List cipherText,
    final Uint8List nonce,
    final Uint8List aData,
  ) {
    final cipher = GCMBlockCipher(
      symmetric.cipherEngine,
    )..init(
        false,
        AEADParameters(
          KeyParameter(key),
          symmetric.blockSize * 8,
          nonce,
          aData,
        ),
      );
    return cipher.process(cipherText);
  }

  @override
  getNonce(
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
