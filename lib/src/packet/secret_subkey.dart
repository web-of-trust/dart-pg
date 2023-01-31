// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'public_subkey.dart';
import 'secret_key.dart';

class SecretSubkeyPacket extends SecretKeyPacket {
  SecretSubkeyPacket(
    super.publicKey,
    super.symmetricAlgorithm,
    super.s2kUsage,
    super.iv,
    super.keyData, {
    super.s2k,
    super.tag = PacketTag.secretSubkey,
  }) : super();

  factory SecretSubkeyPacket.fromPacketData(final Uint8List bytes) {
    final secretKey = SecretSubkeyPacket.fromPacketData(bytes);
    final publicKey = secretKey.publicKey;
    return SecretSubkeyPacket(
      PublicSubkeyPacket(
        publicKey.version,
        publicKey.creationTime,
        publicKey.publicParams,
        expirationDays: publicKey.expirationDays,
        algorithm: publicKey.algorithm,
      ),
      secretKey.symmetricAlgorithm,
      secretKey.s2kUsage,
      secretKey.iv,
      secretKey.keyData,
      s2k: secretKey.s2k,
    );
  }
}
