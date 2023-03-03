// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../helpers.dart';
import 'session_key.dart';
import 'session_key_params.dart';

/// Algorithm Specific Params for RSA encryption
class RSASessionKeyParams extends SessionKeyParams {
  /// multiprecision integer (MPI) of RSA encrypted value m**e mod n.
  final BigInt encrypted;

  RSASessionKeyParams(this.encrypted);

  factory RSASessionKeyParams.fromPacketData(final Uint8List bytes) => RSASessionKeyParams(Helper.readMPI(bytes));

  factory RSASessionKeyParams.encryptSessionKey(final RSAPublicKey key, final SessionKey sessionKey) {
    return RSASessionKeyParams(
      _processInBlocks(
        AsymmetricBlockCipher('RSA')..init(true, PublicKeyParameter<RSAPublicKey>(key)),
        Helper.emeEncode(
          Uint8List.fromList([
            ...sessionKey.encode(),
            ...sessionKey.checksum(),
          ]),
          key.modulus!.byteLength,
        ),
      ).toBigIntWithSign(1),
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...encrypted.bitLength.pack16(),
        ...encrypted.toUnsignedBytes(),
      ]);

  SessionKey decrypt(final RSAPrivateKey key) {
    return decodeSessionKey(
      Helper.emeDecode(
        _processInBlocks(
          AsymmetricBlockCipher('RSA')..init(false, PrivateKeyParameter<RSAPrivateKey>(key)),
          encrypted.toUnsignedBytes(),
        ),
      ),
    );
  }

  static Uint8List _processInBlocks(final AsymmetricBlockCipher engine, final Uint8List input) {
    final numBlocks = input.length ~/ engine.inputBlockSize + ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

    final output = Uint8List(numBlocks * engine.outputBlockSize);

    var inputOffset = 0;
    var outputOffset = 0;
    while (inputOffset < input.length) {
      final chunkSize =
          (inputOffset + engine.inputBlockSize <= input.length) ? engine.inputBlockSize : input.length - inputOffset;

      outputOffset += engine.processBlock(input, inputOffset, chunkSize, output, outputOffset);

      inputOffset += chunkSize;
    }

    return (output.length == outputOffset) ? output : output.sublist(0, outputOffset);
  }
}
