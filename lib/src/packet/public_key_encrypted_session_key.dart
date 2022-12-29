// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/byte_utils.dart';

import '../enums.dart';
import 'contained_packet.dart';

/// PublicKeyEncryptedSessionKey represents a public-key encrypted session key.
/// See RFC 4880, section 5.1.
class PublicKeyEncryptedSessionKey extends ContainedPacket {
  final int version;

  final int keyID;

  final KeyAlgorithm keyAlgorithm;

  final Uint8List encrypted;

  PublicKeyEncryptedSessionKey(
    this.version,
    this.keyID,
    this.keyAlgorithm,
    this.encrypted, {
    super.tag = PacketTag.publicKeyEncryptedSessionKey,
  });

  factory PublicKeyEncryptedSessionKey.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    final keyID = ByteUtils.bytesToInt64(bytes.sublist(pos, pos + 8));

    pos += 8;
    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    return PublicKeyEncryptedSessionKey(version, keyID, keyAlgorithm, bytes.sublist(pos));
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      ...ByteUtils.int64Bytes(keyID),
      keyAlgorithm.value,
      ...encrypted,
    ]);
  }
}
