// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/export.dart';

import '../crypto/symmetric/base_cipher.dart';

/// Symmetric-Key Algorithms
/// See https://tools.ietf.org/html/rfc4880#section-9.2
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

  int get keySize {
    switch (this) {
      case plaintext:
        return 0;
      case idea:
      case cast5:
      case blowfish:
      case aes128:
      case camellia128:
        return 128;
      case tripledes:
      case aes192:
      case camellia192:
        return 192;
      case aes256:
      case twofish:
      case camellia256:
        return 256;
    }
  }

  int get keySizeInByte {
    return (keySize + 7) >> 3;
  }

  int get blockSize {
    switch (this) {
      case plaintext:
        return 0;
      case blowfish:
      case cast5:
      case idea:
      case tripledes:
        return 8;
      case aes128:
      case aes192:
      case aes256:
      case camellia128:
      case camellia192:
      case camellia256:
      case twofish:
        return 16;
    }
  }

  BlockCipher get cfbCipherEngine {
    switch (this) {
      case aes128:
      case aes192:
      case aes256:
        return BlockCipher('AES/CFB-${blockSize * 8}');
      case blowfish:
        return CFBBlockCipher(BlowfishEngine(), blockSize);
      case camellia128:
      case camellia192:
      case camellia256:
        return CFBBlockCipher(CamelliaEngine(), blockSize);
      case cast5:
        return CFBBlockCipher(CAST5Engine(), blockSize);
      case idea:
        return CFBBlockCipher(IDEAEngine(), blockSize);
      case tripledes:
        return BlockCipher('DESede/CFB-${blockSize * 8}');
      case twofish:
        return CFBBlockCipher(TwofishEngine(), blockSize);
      default:
        throw UnsupportedError('Unsupported symmetric algorithm encountered');
    }
  }

  BlockCipher get cipherEngine {
    switch (this) {
      case aes128:
      case aes192:
      case aes256:
        return AESEngine();
      case blowfish:
        return BlowfishEngine();
      case camellia128:
      case camellia192:
      case camellia256:
        return CamelliaEngine();
      case cast5:
        return CAST5Engine();
      case idea:
        return IDEAEngine();
      case tripledes:
        return DESedeEngine();
      case twofish:
        return TwofishEngine();
      default:
        throw UnsupportedError('Unsupported symmetric algorithm encountered');
    }
  }
}
