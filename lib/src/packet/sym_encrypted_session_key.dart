// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../key/s2k.dart';
import 'contained_packet.dart';

/// SymmetricKeyEncrypted represents a passphrase protected session key.
/// See RFC 4880, section 5.3.
class SymEncryptedSessionKey extends ContainedPacket {
  static const tag = PacketTag.symEncryptedSessionKey;

  final int version;

  final SymmetricAlgorithm symmetricAlgorithm;

  final S2K s2k;

  final Uint8List keyData;

  SymEncryptedSessionKey(this.version, this.symmetricAlgorithm, this.s2k, this.keyData);

  factory SymEncryptedSessionKey.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    final symmetricAlgorithm = SymmetricAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    final s2k = S2K.fromPacketData(bytes.sublist(pos));

    return SymEncryptedSessionKey(version, symmetricAlgorithm, s2k, bytes.sublist(pos + s2k.encode().length));
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      symmetricAlgorithm.value,
      ...s2k.encode(),
      ...keyData,
    ]);
  }
}
