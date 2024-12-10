/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Notation data interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class NotationDataInterface {
  /// Get notation name
  String get notationName;

  /// Get notation value
  String get notationValue;

  /// Is human readable
  bool get humanReadable;
}
