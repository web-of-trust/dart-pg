// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum DHKeySize {
  l1024n160(1024, 160),
  l2048n224(2048, 224),
  l2048n256(2048, 256),
  l3072n256(3072, 256);

  final int lSize;

  final int nSize;

  const DHKeySize(this.lSize, this.nSize);
}
