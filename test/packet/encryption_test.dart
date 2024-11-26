import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/aead_algorithm.dart';
import 'package:dart_pg/src/enum/symmetric_algorithm.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/type/literal_data.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('Aead encrypted decryption', () {
    const literalText = 'Hello, world!\n';

    test('Decrypt eax', () {
      final bytes =
          '0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476'
              .hexToBytes();

      final aepd = AeadEncryptedDataPacket.fromBytes(bytes);
      expect(aepd.symmetric, SymmetricAlgorithm.aes128);
      expect(aepd.aead, AeadAlgorithm.eax);
      expect(aepd.chunkSize, 14);
      expect(aepd.iv.toHexadecimal(), 'b732379f73c4928de25facfe6517ec10');

      final decryptAepd = aepd.decrypt('86f1efb86952329f24acd3bfd0e5346d'.hexToBytes());
      final literalData = decryptAepd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt ocb', () {
      final bytes =
          '0107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098'
              .hexToBytes();

      final aepd = AeadEncryptedDataPacket.fromBytes(bytes);
      expect(aepd.symmetric, SymmetricAlgorithm.aes128);
      expect(aepd.aead, AeadAlgorithm.ocb);
      expect(aepd.chunkSize, 14);
      expect(aepd.iv.toHexadecimal(), '5ed2bc1e470abe8f1d644c7a6c8a56');

      final decryptAepd = aepd.decrypt('d1f01ba30e130aa7d2582c16e050ae44'.hexToBytes());
      final literalData = decryptAepd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });
  });

  group('Symmetrically decryption', () {});

  group('Symmetrically encryption', () {
    final literalData = LiteralDataPacket.fromText(
      faker.randomGenerator.string(1000),
    );
    final packets = PacketList([literalData]);
    final key = Helper.generateEncryptionKey(
      SymmetricAlgorithm.aes128,
    ); // encryption key

    test('Encrypt SED', () {
      final encrypted = SymEncryptedDataPacket.encryptPackets(
        key,
        packets,
        symmetric: SymmetricAlgorithm.aes128,
      );
      final encrypt = SymEncryptedDataPacket.fromBytes(
        encrypted.data,
      );

      expect(
        () => encrypt.decrypt(
          key,
          symmetric: SymmetricAlgorithm.aes128,
        ),
        throwsStateError,
      );
    });

    test('Encrypt V1 SEIPD', () {
      final encrypted = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        key,
        packets,
        symmetric: SymmetricAlgorithm.aes128,
      );
      expect(encrypted.version, 1);
      expect(encrypted.symmetric, isNull);
      expect(encrypted.aead, isNull);

      final decrypted = SymEncryptedIntegrityProtectedDataPacket.fromBytes(
        encrypted.data,
      ).decrypt(
        key,
        symmetric: SymmetricAlgorithm.aes128,
      );
      final ldPacket = decrypted.packets!.elementAt(0);
      expect(ldPacket.data, equals(literalData.data));
    });

    test('Encrypt V2 SEIPD', () {
      final encrypted = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        key,
        packets,
        symmetric: SymmetricAlgorithm.aes128,
        aead: AeadAlgorithm.gcm,
        aeadProtect: true,
      );
      expect(encrypted.version, 2);
      expect(encrypted.symmetric, SymmetricAlgorithm.aes128);
      expect(encrypted.aead, AeadAlgorithm.gcm);

      final decrypted = SymEncryptedIntegrityProtectedDataPacket.fromBytes(
        encrypted.data,
      ).decrypt(key);
      final ldPacket = decrypted.packets!.elementAt(0);
      expect(ldPacket.data, equals(literalData.data));
    });
  });

  group('Password protected session key', () {});

  group('Public key protected session key', () {});
}
