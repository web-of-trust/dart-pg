/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// RSA key sizes enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum RSAKeySize {
  normal(2048),
  medium(2560),
  high(3072),
  veryHigh(3584),
  ultraHigh(4096);

  final int bits;

  const RSAKeySize(this.bits);
}
