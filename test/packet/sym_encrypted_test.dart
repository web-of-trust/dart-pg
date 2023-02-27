import 'package:dart_pg/src/helpers.dart';
import 'package:dart_pg/src/packet/literal_data.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/sym_encrypted_data.dart';
import 'package:dart_pg/src/packet/sym_encrypted_integrity_protected_data.dart';
import 'package:dart_pg/src/packet/sym_encrypted_session_key.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('symmetrically', () {
    final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(100));
    final packets = PacketList([literalData]);
    final key = Helper.generateEncryptionKey();
    final passphrase = 'hello';

    test('encrypted data test', () {
      final encrypted = SymEncryptedDataPacket.encryptPackets(key, packets);
      final encrypt = SymEncryptedDataPacket.fromPacketData(encrypted.toPacketData());
      final decrypted = encrypt.decrypt(key);
      final decryptedLD = decrypted.packets![0];
      expect(decryptedLD.toPacketData(), equals(literalData.toPacketData()));
    });

    test('encrypted integrity protected test', () {
      final encrypted = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(key, packets);
      final encrypt = SymEncryptedIntegrityProtectedDataPacket.fromPacketData(encrypted.toPacketData());
      final decrypted = encrypt.decrypt(key);
      final decryptedLD = decrypted.packets![0];
      expect(decryptedLD.toPacketData(), equals(literalData.toPacketData()));
    });

    test('passphrase protected session key test', () {
      final skesk = SymEncryptedSessionKeyPacket.encryptSessionKey(passphrase);
      final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        skesk.sessionKey!.key,
        packets,
        symmetric: skesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([skesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.packetEncode());

      final skeskPacket = packetList.whereType<SymEncryptedSessionKeyPacket>().elementAt(0).decrypt(passphrase);
      expect(skesk.sessionKey, equals(skeskPacket.sessionKey));

      final decrypted = packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            skesk.sessionKey!.key,
            symmetric: skeskPacket.sessionKey!.symmetric,
          );
      final literalPacket = decrypted.packets![0];
      expect(literalPacket.toPacketData(), equals(literalData.toPacketData()));
    });
  });
}
