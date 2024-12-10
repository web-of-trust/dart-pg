import 'package:dart_pg/src/enum/compression_algorithm.dart';
import 'package:dart_pg/src/packet/compressed_data.dart';
import 'package:dart_pg/src/packet/literal_data.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('Compression', () {
    final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(10000));

    test('zip test', () {
      final compressedPacket = CompressedDataPacket.fromPacketList(
        PacketList([literalData]),
        algorithm: CompressionAlgorithm.zip,
      );

      final decompressedPacket = CompressedDataPacket.fromBytes(
        compressedPacket.data,
      );

      expect(
        compressedPacket.algorithm,
        equals(decompressedPacket.algorithm),
      );
      expect(
        compressedPacket.compressed,
        equals(decompressedPacket.compressed),
      );
      expect(
        compressedPacket.packets[0].encode(),
        equals(literalData.encode()),
      );
    });

    test('zlib test', () {
      final compressedPacket = CompressedDataPacket.fromPacketList(
        PacketList([literalData]),
        algorithm: CompressionAlgorithm.zlib,
      );

      final decompressedPacket = CompressedDataPacket.fromBytes(
        compressedPacket.data,
      );

      expect(
        compressedPacket.algorithm,
        equals(decompressedPacket.algorithm),
      );
      expect(
        compressedPacket.compressed,
        equals(decompressedPacket.compressed),
      );
      expect(
        compressedPacket.packets[0].encode(),
        equals(literalData.encode()),
      );
    });

    test('bzip2 test', () {
      expect(
        () => CompressedDataPacket.fromPacketList(
          PacketList([literalData]),
          algorithm: CompressionAlgorithm.bzip2,
        ),
        throwsUnsupportedError,
      );
    });
  });
}
