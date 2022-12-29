// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum RevocationKeyTag {
  classDefault(0x80),
  classSensitive(0x40);

  final int value;
  const RevocationKeyTag(this.value);
}
