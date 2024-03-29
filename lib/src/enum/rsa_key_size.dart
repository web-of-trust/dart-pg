// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum RSAKeySize {
  s2048(2048),
  s2560(2560),
  s3072(3072),
  s3584(3584),
  s4096(4096);

  final int bits;

  const RSAKeySize(this.bits);
}
