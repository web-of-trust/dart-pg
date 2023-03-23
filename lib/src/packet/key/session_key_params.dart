// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../enum/symmetric_algorithm.dart';
import 'session_key.dart';

export 'ecdh_session_key_params.dart';
export 'elgamal_session_key_params.dart';
export 'rsa_session_key_params.dart';

/// Session key params
abstract class SessionKeyParams {
  Uint8List encode();

  SessionKey decodeSessionKey(final Uint8List data) {
    final sessionKeySymmetric =
        SymmetricAlgorithm.values.firstWhere((algo) => algo.value == data[0]);
    final sessionKey =
        SessionKey(data.sublist(1, data.length - 2), sessionKeySymmetric);
    final checksum = data.sublist(data.length - 2);
    final computedChecksum = sessionKey.computeChecksum();
    final isValidChecksum = (computedChecksum[0] == checksum[0]) &&
        (computedChecksum[1] == checksum[1]);
    if (!isValidChecksum) {
      throw StateError('Session key decryption error');
    }
    return sessionKey;
  }

  static Uint8List processInBlocks(
    final AsymmetricBlockCipher engine,
    final Uint8List input,
  ) {
    final numBlocks = input.length ~/ engine.inputBlockSize +
        ((input.lengthInBytes % engine.inputBlockSize != 0) ? 1 : 0);

    final output = Uint8List(numBlocks * engine.outputBlockSize);

    var inpOff = 0;
    var outOff = 0;
    while (inpOff < input.length) {
      final chunkSize = (inpOff + engine.inputBlockSize <= input.lengthInBytes)
          ? engine.inputBlockSize
          : input.lengthInBytes - inpOff;

      outOff += engine.processBlock(
        input,
        inpOff,
        chunkSize,
        output,
        outOff,
      );

      inpOff += chunkSize;
    }

    return (output.length == outOff) ? output : output.sublist(0, outOff);
  }
}
