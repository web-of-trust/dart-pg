/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/s2k_type.dart';

/// String-to-key interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class S2kInterface {
  /// Get S2K type
  S2kType get type;

  /// Get salt
  Uint8List get salt;

  /// Get length
  int get length;

  /// Serialize s2k information to bytes
  Uint8List get toBytes;

  /// Produce a key using the specified passphrase and the defined hash algorithm
  Uint8List produceKey(final String passphrase, final int length);
}
