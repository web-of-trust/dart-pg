// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';
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
    final keyID = bytes.sublist(pos, pos + 8).toInt64();

    pos += 8;
    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    return PublicKeyEncryptedSessionKey(version, keyID, keyAlgorithm, bytes.sublist(pos));
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      ...keyID.unpack64(),
      keyAlgorithm.value,
      ...encrypted,
    ]);
  }
}
