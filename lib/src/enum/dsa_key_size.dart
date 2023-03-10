// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum DSAKeySize {
  l1024n160,
  l2048n224,
  l2048n256,
  l3072n256;

  int get lSize {
    switch (this) {
      case l1024n160:
        return 1024;
      case l2048n224:
        return 2048;
      case l2048n256:
        return 2048;
      case l3072n256:
        return 3072;
    }
  }

  int get nSize {
    switch (this) {
      case l1024n160:
        return 160;
      case l2048n224:
        return 224;
      case l2048n256:
        return 256;
      case l3072n256:
        return 256;
    }
  }
}
