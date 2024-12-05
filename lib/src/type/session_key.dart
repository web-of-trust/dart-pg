/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/symmetric_algorithm.dart';

/// Session key interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SessionKeyInterface {
  /// Get encryption key
  Uint8List get encryptionKey;

  /// Get algorithm to encrypt the message with
  SymmetricAlgorithm get symmetric;

  /// Checksum the encryption key
  void checksum(final Uint8List checksum);

  /// Compute checksum
  Uint8List computeChecksum();

  /// Serialize session key to bytes
  Uint8List toBytes();
}
