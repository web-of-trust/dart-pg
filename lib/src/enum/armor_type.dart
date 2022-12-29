// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum ArmorType {
  multipartSection(0),
  multipartLast(1),
  signedMessage(2),
  message(3),
  publicKey(4),
  privateKey(5),
  signature(6);

  final int value;

  const ArmorType(this.value);
}
