import 'package:dart_pg/src/enum/compression_algorithm.dart';
import 'package:dart_pg/src/packet/compressed_data.dart';
import 'package:dart_pg/src/packet/literal_data.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('Compression', () {
    final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(1000));

    test('zip test', () {
      final compressedPacket = CompressedDataPacket.fromPacketList(
        PacketList([literalData]),
        algorithm: CompressionAlgorithm.zip,
      );

      final compressedData = compressedPacket.toPacketData();
      final decompressedPacket = CompressedDataPacket.fromPacketData(compressedData);

      expect(compressedPacket.algorithm, equals(decompressedPacket.algorithm));
      expect(compressedPacket.compressed, equals(decompressedPacket.compressed));
      expect(compressedPacket.packets[0].toPacketData(), equals(literalData.toPacketData()));
    });

    test('zlib test', () {
      final compressedPacket = CompressedDataPacket.fromPacketList(
        PacketList([literalData]),
        algorithm: CompressionAlgorithm.zlib,
      );

      final compressedData = compressedPacket.toPacketData();
      final decompressedPacket = CompressedDataPacket.fromPacketData(compressedData);

      expect(compressedPacket.algorithm, equals(decompressedPacket.algorithm));
      expect(compressedPacket.compressed, equals(decompressedPacket.compressed));
      expect(compressedPacket.packets[0].toPacketData(), equals(literalData.toPacketData()));
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
