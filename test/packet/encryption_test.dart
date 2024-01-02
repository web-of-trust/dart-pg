import 'dart:convert';

import 'package:dart_pg/src/enum/aead_algorithm.dart';
import 'package:dart_pg/src/enum/symmetric_algorithm.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:dart_pg/src/packet/aead_encrypted_data.dart';
import 'package:dart_pg/src/packet/key/session_key.dart';
import 'package:dart_pg/src/packet/key_packet.dart';
import 'package:dart_pg/src/packet/literal_data.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/public_key_encrypted_session_key.dart';
import 'package:dart_pg/src/packet/sym_encrypted_data.dart';
import 'package:dart_pg/src/packet/sym_encrypted_integrity_protected_data.dart';
import 'package:dart_pg/src/packet/sym_encrypted_session_key.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  group('symmetrically', () {
    final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(1000));
    final packets = PacketList([literalData]);
    final key = Helper.generateEncryptionKey(); // encryption key
    final kek = faker.randomGenerator.string(10); // key encryption key

    test('encrypted data test', () async {
      final encrypted = await SymEncryptedDataPacket.encryptPackets(key, packets);
      final encrypt = SymEncryptedDataPacket.fromByteData(encrypted.toByteData());
      final decrypted = await encrypt.decrypt(key, allowUnauthenticatedMessages: true);
      final ldPacket = decrypted.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));

      expect(
        () => encrypt.decrypt(key),
        throwsStateError,
      );
    });

    test('encrypted integrity protected test', () async {
      final encrypted = await SymEncryptedIntegrityProtectedDataPacket.encryptPackets(key, packets);
      final decrypted =
          await SymEncryptedIntegrityProtectedDataPacket.fromByteData(encrypted.toByteData()).decrypt(key);
      final ldPacket = decrypted.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('password protected session key test', () async {
      final skesk = await SymEncryptedSessionKeyPacket.encryptSessionKey(kek, sessionKey: SessionKey.produceKey());
      final seip = await SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        skesk.sessionKey!.key,
        packets,
        symmetric: skesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([skesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedSkesk = await packetList.whereType<SymEncryptedSessionKeyPacket>().elementAt(0).decrypt(kek);
      expect(skesk.sessionKey!.symmetric, equals(decryptedSkesk.sessionKey!.symmetric));
      expect(skesk.sessionKey!.key, equals(decryptedSkesk.sessionKey!.key));

      final decryptedSeip = await packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
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

    test('rsa test', () async {
      final secretKey = await SecretSubkeyPacket.fromByteData(
        base64.decode(rsaSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);

      final pkesk =
          await PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(secretKey.publicKey, SessionKey.produceKey());
      final seip = await SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk =
          await packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = await packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('elgamal test', () async {
      final secretKey = await SecretSubkeyPacket.fromByteData(
        base64.decode(elgamalSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);

      final pkesk =
          await PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(secretKey.publicKey, SessionKey.produceKey());
      final seip = await SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk =
          await packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = await packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('ecdh test', () async {
      final secretKey = await SecretSubkeyPacket.fromByteData(
        base64.decode(ecdhSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);
      final publicKey = PublicSubkeyPacket.fromByteData(
        base64.decode(ecdhPublicSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      );

      final pkesk = await PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(publicKey, SessionKey.produceKey());
      final seip = await SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk =
          await packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = await packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });

    test('curve25519 test', () async {
      final secretKey = await SecretSubkeyPacket.fromByteData(
        base64.decode(curve25519SecretSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      ).decrypt(passphrase);
      final publicKey = PublicSubkeyPacket.fromByteData(
        base64.decode(curve25519PublicSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')),
      );

      final pkesk = await PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(publicKey, SessionKey.produceKey());
      final seip = await SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        pkesk.sessionKey!.key,
        packets,
        symmetric: pkesk.sessionKey!.symmetric,
      );

      final encryptedList = PacketList([pkesk, seip]);
      final packetList = PacketList.packetDecode(encryptedList.encode());

      final decryptedPkesk =
          await packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().elementAt(0).decrypt(secretKey);
      expect(pkesk.sessionKey!.symmetric, equals(decryptedPkesk.sessionKey!.symmetric));
      expect(pkesk.sessionKey!.key, equals(decryptedPkesk.sessionKey!.key));

      final decryptedSeip = await packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>().elementAt(0).decrypt(
            decryptedPkesk.sessionKey!.key,
            symmetric: decryptedPkesk.sessionKey!.symmetric,
          );
      final ldPacket = decryptedSeip.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });
  });

  group('aead encrypted data', () {
    test('test eax decrypt', () async {
      final key = '86f1efb86952329f24acd3bfd0e5346d'.hexToBytes();
      final iv = 'b732379f73c4928de25facfe6517ec10'.hexToBytes();
      final bytes =
          '0107010eb732379f73c4928de25facfe6517ec105dc11a81dc0cb8a2f6f3d90016384a56fc821ae11ae8dbcb49862655dea88d06a81486801b0ff387bd2eab013de1259586906eab2476'
              .hexToBytes();

      final eax = await AeadEncryptedData.fromByteData(bytes).decrypt(key);
      expect(eax.symmetric, SymmetricAlgorithm.aes128);
      expect(eax.aead, AeadAlgorithm.eax);
      expect(eax.chunkSize, 14);
      expect(eax.iv, equals(iv));

      final ldPacket = eax.packets![0] as LiteralDataPacket;
      expect(utf8.decode(ldPacket.data), "Hello, world!\n");
    });

    test('test ocb decrypt', () async {
      final key = 'd1f01ba30e130aa7d2582c16e050ae44'.hexToBytes();
      final iv = '5ed2bc1e470abe8f1d644c7a6c8a56'.hexToBytes();
      final bytes =
          '0107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098'
              .hexToBytes();

      final ocb = await AeadEncryptedData.fromByteData(bytes).decrypt(key);
      expect(ocb.symmetric, SymmetricAlgorithm.aes128);
      expect(ocb.aead, AeadAlgorithm.ocb);
      expect(ocb.chunkSize, 14);
      expect(ocb.iv, equals(iv));

      final ldPacket = ocb.packets![0] as LiteralDataPacket;
      expect(utf8.decode(ldPacket.data), "Hello, world!\n");
    });

    test('test encrypt', () async {
      final literalData = LiteralDataPacket.fromText(faker.randomGenerator.string(1000));
      final packets = PacketList([literalData]);
      final key = Helper.generateEncryptionKey(SymmetricAlgorithm.aes256);

      final encrypted = await AeadEncryptedData.encryptPackets(key, packets);
      expect(encrypted.symmetric, SymmetricAlgorithm.aes256);
      expect(encrypted.aead, AeadAlgorithm.ocb);
      expect(encrypted.chunkSize, 12);

      final decrypted = await AeadEncryptedData.fromByteData(encrypted.toByteData()).decrypt(key);
      final ldPacket = decrypted.packets![0];
      expect(ldPacket.toByteData(), equals(literalData.toByteData()));
    });
  });
}
