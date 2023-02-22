// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../openpgp.dart';
import 'contained_packet.dart';
import 'key/key_id.dart';

/// PublicKeyEncryptedSessionKey represents a public-key encrypted session key.
/// See RFC 4880, section 5.1.
class PublicKeyEncryptedSessionKeyPacket extends ContainedPacket {
  final int version;

  final KeyID keyID;

  final KeyAlgorithm keyAlgorithm;

  final Uint8List encrypted;

  PublicKeyEncryptedSessionKeyPacket(
    this.keyID,
    this.keyAlgorithm,
    this.encrypted, {
    this.version = OpenPGP.pkeskVersion,
    super.tag = PacketTag.publicKeyEncryptedSessionKey,
  });

  factory PublicKeyEncryptedSessionKeyPacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    if (version != OpenPGP.pkeskVersion) {
      throw UnsupportedError('Version $version of the PKESK packet is unsupported.');
    }

    final keyID = bytes.sublist(pos, pos + 8);
    pos += 8;

    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;

    return PublicKeyEncryptedSessionKeyPacket(KeyID(keyID), keyAlgorithm, bytes.sublist(pos), version: version);
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      ...keyID.id,
      keyAlgorithm.value,
      ...encrypted,
    ]);
  }
}
