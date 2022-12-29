// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum RevocationReasonTag {
  noReason(0),
  keySuperseded(1),
  keyCompromised(2),
  keyRetired(3),
  userIDInvalid(32);

  final int value;

  const RevocationReasonTag(this.value);
}
