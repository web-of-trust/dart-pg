// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

class CompressedData extends ContainedPacket {
  final CompressionAlgorithm algorithm;

  final int deflateLevel;

  final Uint8List compressed;

  CompressedData(
    this.compressed, {
    this.algorithm = CompressionAlgorithm.uncompressed,
    this.deflateLevel = 6,
    super.tag = PacketTag.compressedData,
  });

  factory CompressedData.fromPacketData(final Uint8List bytes) {
    final algorithm = CompressionAlgorithm.values.firstWhere((algo) => algo.value == bytes[0]);
    return CompressedData(bytes.sublist(1), algorithm: algorithm);
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([algorithm.value, ...compressed]);
  }
}
