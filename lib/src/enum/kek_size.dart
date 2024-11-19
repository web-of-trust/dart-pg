/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Key encryption key size enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum KekSize {
  normal(16),
  medium(24),
  high(32);

  final int size;

  const KekSize(this.size);
}
