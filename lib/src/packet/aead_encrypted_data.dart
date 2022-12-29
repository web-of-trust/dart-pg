// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

/// Implementation of the Symmetrically Encrypted Authenticated Encryption with
/// Additional Data (AEAD) Protected Data Packet
class AEADEncryptedData extends ContainedPacket {
  static const tag = PacketTag.aeadEncryptedData;

  final int version;

  final SymmetricAlgorithm symmetricAlgorithm;

  final AeadAlgorithm aeadAlgorithm;

  final int chunkSizeByte;

  final Uint8List iv;

  final Uint8List encrypted;

  AEADEncryptedData(
    this.version,
    this.symmetricAlgorithm,
    this.aeadAlgorithm,
    this.chunkSizeByte,
    this.iv,
    this.encrypted,
  );

  factory AEADEncryptedData.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    final symmetricAlgorithm = SymmetricAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    final aeadAlgorithm = AeadAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    final chunkSizeByte = bytes[pos++];
    final ivLength = IvLength.values.firstWhere((iv) => iv.name == aeadAlgorithm.name);

    return AEADEncryptedData(
      version,
      symmetricAlgorithm,
      aeadAlgorithm,
      chunkSizeByte,
      bytes.sublist(pos, pos + ivLength.value),
      bytes.sublist(pos + ivLength.value),
    );
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      symmetricAlgorithm.value,
      aeadAlgorithm.value,
      chunkSizeByte,
      ...iv,
      ...encrypted,
    ]);
  }
}
