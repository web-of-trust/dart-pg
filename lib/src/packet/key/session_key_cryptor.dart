/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/api.dart';

import '../../type/session_key.dart';
import '../../type/session_key_cryptor.dart';
import 'session_key.dart';

export 'ecdh_session_key_cryptor.dart';
export 'elgamal_session_key_cryptor.dart';
export 'montgomery_session_key_cryptor.dart';
export 'rsa_session_key_cryptor.dart';
export 'session_key.dart';

/// Abstract session key cryptor class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class SessionKeyCryptor implements SessionKeyCryptorInterface {
  static SessionKeyInterface decodeSessionKey(final Uint8List data) {
    return SessionKey.fromBytes(data);
  }

  static Uint8List processInBlocks(
    final AsymmetricBlockCipher engine,
    final Uint8List input,
  ) {
    final numBlocks =
        input.length ~/ engine.inputBlockSize + ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

    final output = Uint8List(numBlocks * engine.outputBlockSize);

    var inpOff = 0;
    var outOff = 0;
    while (inpOff < input.length) {
      final chunkSize =
          (inpOff + engine.inputBlockSize <= input.length)
          ? engine.inputBlockSize
          : input.length - inpOff;

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
