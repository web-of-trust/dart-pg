// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum S2kUsage {
  none(0),
  checksum(255),
  sha1(254),
  aeadProtect(253);

  final int value;

  const S2kUsage(this.value);
}
