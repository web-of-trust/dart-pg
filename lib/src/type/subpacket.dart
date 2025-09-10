/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/signature_subpacket_type.dart';

/// Subpacket interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SubpacketInterface {
  /// Get sub-packet type
  SignatureSubpacketType get type;

  /// Get sub-packet data
  Uint8List get data;

  /// Serialize sub-packet to bytes
  Uint8List encode();
}
