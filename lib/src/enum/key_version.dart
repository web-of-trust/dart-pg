/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Key versions enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum KeyVersion {
  v4(4),
  v6(6);

  final int value;

  const KeyVersion(this.value);
}
