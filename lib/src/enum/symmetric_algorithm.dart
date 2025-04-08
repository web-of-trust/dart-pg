// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/export.dart';

import '../cryptor/symmetric/cast5.dart';
import '../cryptor/symmetric/idea.dart';

/// Symmetric key algorithms enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum SymmetricAlgorithm {
  plaintext(0),
  idea(1),
  tripledes(2),
  cast5(3),
  blowfish(4),
  aes128(7),
  aes192(8),
  aes256(9),
  twofish(10),
  camellia128(11),
  camellia192(12),
  camellia256(13);

  final int value;

  const SymmetricAlgorithm(this.value);

  static List<SymmetricAlgorithm> get preferredSymmetrics => [
        aes128,
        aes192,
        aes256,
        camellia128,
        camellia192,
        camellia256,
        blowfish,
        twofish,
      ];

  int get keySize => switch (this) {
        plaintext => 0,
        idea || cast5 || blowfish || aes128 || camellia128 => 128,
        tripledes || aes192 || camellia192 => 192,
        aes256 || twofish || camellia256 => 256,
      };

  int get keySizeInByte => (keySize + 7) >> 3;

  int get blockSize => switch (this) {
        plaintext => 0,
        blowfish || cast5 || idea || tripledes => 8,
        aes128 ||
        aes192 ||
        aes256 ||
        camellia128 ||
        camellia192 ||
        camellia256 ||
        twofish =>
          16,
      };

  BlockCipher get cfbCipherEngine => switch (this) {
        aes128 || aes192 || aes256 => BlockCipher('AES/CFB-${blockSize * 8}'),
        blowfish => CFBBlockCipher(BlowfishEngine(), blockSize),
        camellia128 ||
        camellia192 ||
        camellia256 =>
          CFBBlockCipher(CamelliaEngine(), blockSize),
        cast5 => CFBBlockCipher(CAST5Engine(), blockSize),
        idea => CFBBlockCipher(IDEAEngine(), blockSize),
        tripledes => BlockCipher('DESede/CFB-${blockSize * 8}'),
        twofish => CFBBlockCipher(TwofishEngine(), blockSize),
        _ =>
          throw UnsupportedError('Unsupported symmetric algorithm encountered'),
      };

  BlockCipher get cipherEngine => switch (this) {
        aes128 || aes192 || aes256 => AESEngine(),
        blowfish => BlowfishEngine(),
        camellia128 || camellia192 || camellia256 => CamelliaEngine(),
        cast5 => CAST5Engine(),
        idea => IDEAEngine(),
        tripledes => DESedeEngine(),
        twofish => TwofishEngine(),
        _ =>
          throw UnsupportedError('Unsupported symmetric algorithm encountered'),
      };
}
