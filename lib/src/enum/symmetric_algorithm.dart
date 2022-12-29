// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum SymmetricAlgorithm {
  plaintext(0),
  idea(1),
  tripledes(2),
  cast5(3),
  blowfish(4),
  aes128(7),
  aes192(8),
  aes256(9),
  twofish(10);

  final int value;

  const SymmetricAlgorithm(this.value);
}
