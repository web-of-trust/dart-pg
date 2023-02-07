// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

/// Implementation of the Symmetrically Encrypted Authenticated Encryption with
/// Additional Data (AEAD) Protected Data Packet
class AEADEncryptedDataPacket extends ContainedPacket {
  final int version;

  final SymmetricAlgorithm symmetricAlgorithm;

  final AeadAlgorithm aeadAlgorithm;

  final int chunkSizeByte;

  final Uint8List iv;

  final Uint8List encrypted;

  AEADEncryptedDataPacket(
    this.version,
    this.symmetricAlgorithm,
    this.aeadAlgorithm,
    this.chunkSizeByte,
    this.iv,
    this.encrypted, {
    super.tag = PacketTag.aeadEncryptedData,
  });

  factory AEADEncryptedDataPacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final version = bytes[pos++];
    final symmetricAlgorithm = SymmetricAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;
    final aeadAlgorithm = AeadAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;
    final chunkSizeByte = bytes[pos++];

    return AEADEncryptedDataPacket(
      version,
      symmetricAlgorithm,
      aeadAlgorithm,
      chunkSizeByte,
      bytes.sublist(pos, pos + aeadAlgorithm.ivLength),
      bytes.sublist(pos + aeadAlgorithm.ivLength),
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
