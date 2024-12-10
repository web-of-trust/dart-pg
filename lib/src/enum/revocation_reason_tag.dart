/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Reason for revocation enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum RevocationReasonTag {
  /// No reason specified (key revocations or cert revocations)
  noReason(0),

  /// Key is superseded (key revocations)
  keySuperseded(1),

  /// Key material has been compromised (key revocations)
  keyCompromised(2),

  /// Key is retired and no longer used (key revocations)
  keyRetired(3),

  /// User ID information is no longer valid (cert revocations)
  userIDInvalid(32);

  final int value;

  const RevocationReasonTag(this.value);
}
