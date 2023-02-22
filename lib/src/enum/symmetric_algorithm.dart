// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pointycastle/api.dart';
import 'package:pointycastle/export.dart';

import '../crypto/symmetric/base_cipher.dart';

/// Symmetric-Key Algorithms
/// See https://tools.ietf.org/html/rfc4880#section-9.2
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

  int get blockSize {
    switch (this) {
      case plaintext:
        return 0;
      case cast5:
      case idea:
      case tripledes:
        return 8;
      case blowfish:
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

  BlockCipher get cipherEngine {
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
        return CFBBlockCipher(TripleDESEngine(), blockSize);
      case twofish:
        return CFBBlockCipher(TwofishEngine(), blockSize);
      default:
        throw UnsupportedError('Unsupported symmetric algorithm encountered');
    }
  }
}
