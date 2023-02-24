import 'dart:typed_data';

import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/packet/literal_data.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/sym_encrypted_data.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('symmetrically encrypted', () {
    test('sym encrypted data test', () {
      final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(100));
      final packets = PacketList([literalData]);
      final key = Uint8List.fromList(
          [1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2]);

      final encrypted = SymEncryptedDataPacket.encryptPackets(SymmetricAlgorithm.aes256, key, packets);
      final encrypt = SymEncryptedDataPacket.fromPacketData(encrypted.toPacketData());
      final decrypted = encrypt.decrypt(SymmetricAlgorithm.aes256, key);
      final decryptedLD = decrypted.packets![0];
      expect(decryptedLD.toPacketData(), equals(literalData.toPacketData()));
    });
  });
}
