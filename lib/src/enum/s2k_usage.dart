// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum S2kUsage {
  none(0),
  checksum(255),
  sha1(254),
  aeadProtect(253);

  final int value;

  const S2kUsage(this.value);
}
