// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:io';
import 'dart:typed_data';

import '../enum/compression_algorithm.dart';
import '../enum/packet_tag.dart';
import 'contained_packet.dart';
import 'packet_list.dart';

/// Implementation of the Compressed Data Packet (Tag 8)
///
/// The Compressed Data packet contains compressed data.
/// Typically, this packet is found as the contents of an encrypted packet,
/// or following a Signature or One-Pass Signature packet, and contains a literal data packet.
class CompressedDataPacket extends ContainedPacket {
  /// Default zip/zlib compression level, between 1 and 9
  static const deflateLevel = 6;

  final CompressionAlgorithm algorithm;

  /// Compressed packet data
  final Uint8List compressed;

  /// Decompressed packets contained within.
  final PacketList packets;

  CompressedDataPacket(
    this.compressed,
    this.packets, {
    this.algorithm = CompressionAlgorithm.uncompressed,
  }) : super(PacketTag.compressedData);

  factory CompressedDataPacket.fromPacketData(final Uint8List bytes) {
    final algorithm = CompressionAlgorithm.values.firstWhere(
      (algo) => algo.value == bytes[0],
      orElse: () => CompressionAlgorithm.uncompressed,
    );
    final compressed = bytes.sublist(1);
    return CompressedDataPacket(
      compressed,
      _decompress(compressed, algorithm),
      algorithm: algorithm,
    );
  }

  factory CompressedDataPacket.fromPacketList(
    final PacketList packets, {
    final CompressionAlgorithm algorithm = CompressionAlgorithm.uncompressed,
  }) {
    return CompressedDataPacket(_compress(packets, algorithm), packets, algorithm: algorithm);
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([algorithm.value, ...compressed]);
  }

  static Uint8List _compress(
    final PacketList packets,
    final CompressionAlgorithm algorithm,
  ) {
    switch (algorithm) {
      case CompressionAlgorithm.zip:
      case CompressionAlgorithm.zlib:
        final codec = ZLibCodec(level: deflateLevel, raw: algorithm == CompressionAlgorithm.zip);
        return Uint8List.fromList(codec.encode(packets.packetEncode()));
      case CompressionAlgorithm.bzip2:
        throw UnsupportedError('Compression algorithm ${algorithm.name} is unsupported.');
      default:
        return packets.packetEncode();
    }
  }

  static PacketList _decompress(
    final Uint8List compressed,
    final CompressionAlgorithm algorithm,
  ) {
    switch (algorithm) {
      case CompressionAlgorithm.zip:
      case CompressionAlgorithm.zlib:
        final codec = ZLibCodec(level: deflateLevel, raw: algorithm == CompressionAlgorithm.zip);
        return PacketList.packetDecode(Uint8List.fromList(codec.decode(compressed)));
      case CompressionAlgorithm.bzip2:
        throw UnsupportedError('Compression algorithm ${algorithm.name} is unsupported.');
      default:
        return PacketList.packetDecode(compressed);
    }
  }
}
