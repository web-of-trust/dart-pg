import 'dart:convert';

import 'package:dart_pg/src/helpers.dart';
import 'package:dart_pg/src/packet/key_packet.dart';
import 'package:dart_pg/src/packet/literal_data.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/public_key_encrypted_session_key.dart';
import 'package:dart_pg/src/packet/sym_encrypted_data.dart';
import 'package:dart_pg/src/packet/sym_encrypted_integrity_protected_data.dart';
import 'package:dart_pg/src/packet/sym_encrypted_session_key.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../test_data.dart';

void main() {
  group('symmetrically', () {
    final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(1000));
    final packets = PacketList([literalData]);
    final key = Helper.generateEncryptionKey(); // encryption key
    final kek = faker.randomGenerator.string(10); // key encryption key

    test('encrypted data test', () {
      final encrypted = SymEncryptedDataPacket.encryptPackets(key, packets);
      final encrypt = SymEncryptedDataPacket.fromByteData(encrypted.toByteData());
      final decrypted = encrypt.decrypt(key, allowUnauthenticatedMessages: true);
      final ldPacket = decrypted.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));

      expect(
        () => encrypt.decrypt(key),
        throwsStateError,
      );
    });

    test('encrypted integrity protected test', () {
      final encrypted = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(key, packets);
      final encrypt = SymEncryptedIntegrityProtectedDataPacket.fromByteData(encrypted.toByteData());
      final decrypted = encrypt.decrypt(key);
      final ldPacket = decrypted.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('password protected session key test', () {
      final skesk = SymEncryptedSessionKeyPacket.encryptSessionKey(kek);
      final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        skesk.sessionKey!.key,
        packets,
        symmetric: skesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([skesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedSkesk = packetList.whereType<SymEncryptedSessionKeyPacket>().elementAt(0).decrypt(kek);
      expect(skesk.sessionKey!.symmetric, equals(decryptedSkesk.sessionKey!.symmetric));
      expect(skesk.sessionKey!.key, equals(decryptedSkesk.sessionKey!.key));

      final decryptedSeip = packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedSkesk.sessionKey!.key,
            symmetric: decryptedSkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });
  });

  group('public key protected', () {
    final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(100));
    final packets = PacketList([literalData]);

    test('rsa test', () {
      final secretKey = SecretSubkeyPacket.fromByteData(
        base64.decode(rsaSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);

      final pkesk = PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(secretKey.publicKey);
      final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk = packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('elgamal test', () {
      final secretKey = SecretSubkeyPacket.fromByteData(
        base64.decode(elgamalSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);

      final pkesk = PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(secretKey.publicKey);
      final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk = packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('ecdh test', () {
      final secretKey = SecretSubkeyPacket.fromByteData(
        base64.decode(ecdhSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);
      final publicKey = PublicSubkeyPacket.fromByteData(
        base64.decode(ecdhPublicSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      );

      final pkesk = PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(publicKey);
      final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk = packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('curve25519 test', () {
      final secretKey = SecretSubkeyPacket.fromByteData(
        base64.decode(curve25519SecretSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);
      final publicKey = PublicSubkeyPacket.fromByteData(
        base64.decode(curve25519PublicSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      );

      final pkesk = PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(publicKey);
      final seip = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk = packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });
  });
}
