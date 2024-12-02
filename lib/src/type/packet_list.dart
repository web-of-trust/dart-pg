/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'packet.dart';

/// Packet list interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class PacketListInterface<T extends PacketInterface> extends Iterable<T> {
  /// Get packets
  Iterable<PacketInterface> get packets;

  /// Serialize packets to bytes
  Uint8List encode();
}
