/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Revocation key tag enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum RevocationKeyTag {
  classDefault(128),
  classSensitive(64);

  final int value;

  const RevocationKeyTag(this.value);
}
