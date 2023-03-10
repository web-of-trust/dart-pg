// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum RSAKeySize {
  s2048,
  s2560,
  s3072,
  s3584,
  s4096;

  int get bits {
    switch (this) {
      case s2048:
        return 2048;
      case s2560:
        return 2560;
      case s3072:
        return 3072;
      case s3584:
        return 3584;
      case s4096:
        return 4096;
    }
  }
}
