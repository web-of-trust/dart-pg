/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../enum/symmetric_algorithm.dart';
import '../../type/aead.dart';

/// EAX Authenticated-Encryption class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class Eax implements AeadInterface {
  final Uint8List key;
  final SymmetricAlgorithm symmetric;

  Eax(this.key, this.symmetric);

  @override
  encrypt(
    final Uint8List plainText,
    final Uint8List nonce,
    final Uint8List aData,
  ) {
    final cipher = EAX(
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

    return _process(cipher, plainText);
  }

  @override
  decrypt(
    final Uint8List cipherText,
    final Uint8List nonce,
    final Uint8List aData,
  ) {
    final cipher = EAX(
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

    return _process(cipher, cipherText);
  }

  @override
  getNonce(
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
