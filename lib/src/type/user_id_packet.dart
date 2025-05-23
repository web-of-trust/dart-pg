/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'packet.dart';

/// User ID packet interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class UserIDPacketInterface implements PacketInterface {
  /// Get bytes for sign
  Uint8List get signBytes;
}
