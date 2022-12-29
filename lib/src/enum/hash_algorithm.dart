// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum HashAlgorithm {
  md5(1),
  sha1(2),
  ripemd(3),
  sha256(8),
  sha384(9),
  sha512(10),
  sha224(11);

  final int value;

  const HashAlgorithm(this.value);
}
