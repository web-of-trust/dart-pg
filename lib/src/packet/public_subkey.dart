/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/packet_type.dart';
import '../type/subkey_packet.dart';
import 'public_key.dart';

/// Implementation of the Public Subkey Packet (Type 14)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PublicSubkeyPacket extends PublicKeyPacket implements SubkeyPacketInterface {
  @override
  PacketType get type => PacketType.publicSubkey;

  PublicSubkeyPacket(
    super.keyVersion,
    super.creationTime,
    super.keyMaterial, {
    super.keyAlgorithm,
  });

  factory PublicSubkeyPacket.fromBytes(final Uint8List bytes) {
    final publicKey = PublicKeyPacket.fromBytes(bytes);
    return PublicSubkeyPacket(
      publicKey.keyVersion,
      publicKey.creationTime,
      publicKey.keyMaterial,
      keyAlgorithm: publicKey.keyAlgorithm,
    );
  }
}
