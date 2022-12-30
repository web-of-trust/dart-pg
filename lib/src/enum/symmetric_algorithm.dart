// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Symmetric-Key Algorithms
/// See https://tools.ietf.org/html/rfc4880#section-9.2
enum SymmetricAlgorithm {
  plaintext(0),
  idea(1),
  tripledes(2),
  cast5(3),
  blowfish(4),
  safer(5),
  des(6),
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
      case des:
        return 64;
      case idea:
      case cast5:
      case blowfish:
      case safer:
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
}
