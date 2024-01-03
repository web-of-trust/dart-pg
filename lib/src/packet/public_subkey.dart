// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enum/packet_tag.dart';
import 'public_key.dart';
import 'subkey_packet.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PublicSubkeyPacket extends PublicKeyPacket implements SubkeyPacket {
  @override
  PacketTag get tag => PacketTag.publicSubkey;

  PublicSubkeyPacket(
    super.createdTime,
    super.publicParams, {
    super.algorithm,
  });

  factory PublicSubkeyPacket.fromByteData(final Uint8List bytes) {
    final publicKey = PublicKeyPacket.fromByteData(bytes);
    return PublicSubkeyPacket(
      publicKey.creationTime,
      publicKey.publicParams,
      algorithm: publicKey.algorithm,
    );
  }
}
