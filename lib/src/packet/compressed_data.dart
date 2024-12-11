/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:io';
import 'dart:typed_data';

import '../enum/compression_algorithm.dart';
import '../type/packet_list.dart';
import 'base_packet.dart';

/// Implementation of the Compressed Data (COMP) Packet - Type 11
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class CompressedDataPacket extends BasePacket {
  /// Default zip/zlib compression level, between 1 and 9
  static const deflateLevel = 6;

  final CompressionAlgorithm algorithm;

  /// Compressed packet data
  final Uint8List compressed;

  /// Decompressed packets contained within.
  final PacketListInterface packets;

  CompressedDataPacket(
    this.compressed,
    this.packets, {
    this.algorithm = CompressionAlgorithm.uncompressed,
  }) : super(PacketType.compressedData);

  factory CompressedDataPacket.fromBytes(final Uint8List bytes) {
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
    final PacketListInterface packets, [
    final CompressionAlgorithm algorithm = CompressionAlgorithm.uncompressed,
  ]) =>
      CompressedDataPacket(
        _compress(packets, algorithm),
        packets,
        algorithm: algorithm,
      );

  @override
  get data => Uint8List.fromList([
        algorithm.value,
        ...compressed,
      ]);

  static Uint8List _compress(
    final PacketListInterface packets,
    final CompressionAlgorithm algorithm,
  ) =>
      switch (algorithm) {
        CompressionAlgorithm.zip ||
        CompressionAlgorithm.zlib =>
          Uint8List.fromList(
            ZLibCodec(
              level: deflateLevel,
              raw: algorithm == CompressionAlgorithm.zip,
            ).encode(packets.encode()),
          ),
        CompressionAlgorithm.bzip2 => throw UnsupportedError(
            'Compression algorithm ${algorithm.name} is unsupported.',
          ),
        _ => packets.encode(),
      };

  static PacketList _decompress(
    final Uint8List compressed,
    final CompressionAlgorithm algorithm,
  ) =>
      switch (algorithm) {
        CompressionAlgorithm.zip ||
        CompressionAlgorithm.zlib =>
          PacketList.decode(
            Uint8List.fromList(ZLibCodec(
              level: deflateLevel,
              raw: algorithm == CompressionAlgorithm.zip,
            ).decode(compressed)),
          ),
        CompressionAlgorithm.bzip2 => throw UnsupportedError(
            'Compression algorithm ${algorithm.name} is unsupported.',
          ),
        _ => PacketList.decode(compressed),
      };
}
