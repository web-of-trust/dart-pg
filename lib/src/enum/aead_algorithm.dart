// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Aead algorithm
enum AeadAlgorithm {
  eax(1),
  ocb(2),
  gcm(100);

  final int value;

  const AeadAlgorithm(this.value);
}
