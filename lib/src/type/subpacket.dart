/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

/// Subpacket interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class Subpacket {
  /// Get sub-packet type
  int get type;

  /// Get sub-packet data
  Uint8List get data;

  /// Is long
  bool get isLong;

  /// Serialize sub-packet to bytes
  Uint8List encode();
}
