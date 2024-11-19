/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/packet_type.dart';

/// Packet interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class PacketInterface {
  /// Get packet type
  PacketType get type;

  /// Get packet data
  Uint8List get data;

  /// Serialize packet to bytes
  Uint8List encode();
}
