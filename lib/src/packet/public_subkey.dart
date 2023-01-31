// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'public_key.dart';
import 'subkey_packet.dart';

class PublicSubkeyPacket extends PublicKeyPacket implements SubkeyPacket {
  PublicSubkeyPacket(
    super.version,
    super.createdTime,
    super.pgpKey, {
    super.expirationDays,
    super.algorithm,
    super.tag = PacketTag.publicSubkey,
  }) : super();

  factory PublicSubkeyPacket.fromPacketData(final Uint8List bytes) {
    final publicKey = PublicKeyPacket.fromPacketData(bytes);
    return PublicSubkeyPacket(
      publicKey.version,
      publicKey.creationTime,
      publicKey.publicParams,
      expirationDays: publicKey.expirationDays,
      algorithm: publicKey.algorithm,
    );
  }
}
