// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../openpgp.dart';
import 'contained_packet.dart';
import 'packet_list.dart';

/// Implementation of the Compressed Data Packet (Tag 8)
///
/// The Compressed Data packet contains compressed data.
/// Typically, this packet is found as the contents of an encrypted packet,
/// or following a Signature or One-Pass Signature packet, and contains a literal data packet.
class CompressedDataPacket extends ContainedPacket {
  static const deflateLevel = OpenPGP.deflateLevel;

  final CompressionAlgorithm algorithm;

  /// Compressed packet data
  final Uint8List compressed;

  /// Decompressed packets contained within.
  final PacketList? packets;

  CompressedDataPacket(
    this.compressed, {
    this.algorithm = OpenPGP.preferredCompression,
    this.packets,
  }) : super(PacketTag.compressedData);

  factory CompressedDataPacket.fromPacketData(final Uint8List bytes) {
    final algorithm = CompressionAlgorithm.values.firstWhere((algo) => algo.value == bytes[0]);
    return CompressedDataPacket(bytes.sublist(1), algorithm: algorithm);
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([algorithm.value, ...compressed]);
  }
}
