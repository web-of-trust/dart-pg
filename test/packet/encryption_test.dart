import 'dart:convert';

import 'package:dart_pg/src/common/argon2_s2k.dart';
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

  group('Symmetrically decryption', () {
    const passphrase = 'password';
    const literalText = "Hello, world!";

    test('Encrypted using aead eax', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'Bh4HAQsDCKWuV50fxdgr/2kiT5GZk7NQb6O1mmpzz/jF78X0HFf7VOHCJoFdeCj1+SxFTrZevgCrWYbGjm58VQ==',
      )).decrypt(passphrase);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.aead, AeadAlgorithm.eax);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '3881bafe985412459b86c36f98cb9a5e'.hexToBytes(),
      );

      final seipd = SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AgcBBp/5DjsyGWTzpCkTyNzGYZMlAVIn77fq6qSfBMLmdBddSj0ibtavy5yprBIsFHDhHGPUwKskHGqTitSL+ZpambkLuoMl3mEEdUAlireVmpWtBR3alusVQx3+9fXiJVyngmFUbjOa',
      )).decrypt(sessionKey.encryptionKey);
      expect(seipd.symmetric, SymmetricAlgorithm.aes128);
      expect(seipd.aead, AeadAlgorithm.eax);

      final literalData = seipd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Encrypted using aead ocb', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'Bh0HAgsDCFaimNL142RT/8/MXBFmTtudtCWQ19xGsHJBthLDgSz/++oA8jR7JWQRI/iHrmDU/WFOCDfYGdNs',
      )).decrypt(passphrase);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.aead, AeadAlgorithm.ocb);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '28e79ab82397d3c63de24ac217d7b791'.hexToBytes(),
      );

      final seipd = SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AgcCBiCmYfcx/JowMrViMyYCfjpdjbV0jr7/CwxZENCezdZB/5/ThWJ1gDW8SXVM4b8//6fa0KO4EE9RM89CpBAKg+70yhtIAaiEa/QrzafIzp1l4hLzAcvNmP3K3mlKh3rUJHMj9uhX',
      )).decrypt(sessionKey.encryptionKey);
      expect(seipd.symmetric, SymmetricAlgorithm.aes128);
      expect(seipd.aead, AeadAlgorithm.ocb);

      final literalData = seipd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Encrypted using aead gcm', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BhoHAwsDCOnTl4WyBwAI/7QufEg+9IhEV8s3Jrmz25/3duX02aQJUuJEcpiFGr//dSbfLdVUQXV5p3mf',
      )).decrypt(passphrase);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.aead, AeadAlgorithm.gcm);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '1936fc8568980274bb900d8319360c77'.hexToBytes(),
      );

      final seipd = SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AgcDBvy5RJC8uYu9ydEGxgkCZpQPcuie3CG1WWsVdrEB7Q+f/G/G1lu/0k3NB5CWbm0ehaMAU3hMsdi2oGme8SFVp7KtYlhTG1dlH9d3eRL6leNdm0Ahb2mkwkjbKP9DMfFjKQc5nm/5',
      )).decrypt(sessionKey.encryptionKey);
      expect(seipd.symmetric, SymmetricAlgorithm.aes128);
      expect(seipd.aead, AeadAlgorithm.gcm);

      final literalData = seipd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });

    test('V4 SKESK Using Argon2 with AES-128', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BAcEnFL4PCf5XlDVNUQOzf8xNgEEFZ5S/K0izz+VZULLp5TvhAsR',
      )).decrypt(passphrase);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.s2k is Argon2S2k, isTrue);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '01fe16bbacfd1e7b78ef3b865187374f'.hexToBytes(),
      );
      expect(sessionKey.symmetric, SymmetricAlgorithm.aes128);

      final seipd = SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AZgYpj5gnPi7oX4MOUME6vk1FBe38okh/ibiY6UrIL+6otumcslkydOrejv0bEFN0h07OEdd8DempXiZPMU=',
      )).decrypt(sessionKey.encryptionKey, symmetric: sessionKey.symmetric);
      final literalData = seipd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });

    test('V4 SKESK Using Argon2 with AES-192', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BAgE4UysRxU0WRipYtyjR+FD+AEEFYcyydr2txRvP6ZqSD3fx/5naFUuVQSy8Bc=',
      )).decrypt(passphrase);
      expect(skesk.symmetric, SymmetricAlgorithm.aes192);
      expect(skesk.s2k is Argon2S2k, isTrue);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '27006dae68e509022ce45a14e569e91001c2955af8dfe194'.hexToBytes(),
      );
      expect(sessionKey.symmetric, SymmetricAlgorithm.aes192);

      final seipd = SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRysLVg77Mwwfgl2n/d572WciAM=',
      )).decrypt(sessionKey.encryptionKey, symmetric: sessionKey.symmetric);
      final literalData = seipd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });

    test('V4 SKESK Using Argon2 with AES-256', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BAkEuHiVICBv95nGiCxCRaZifAEEFZ2fZeyrWoHQpZvVGkP2ejP+a6JJUhqRrutt2Jml3sxo/A==',
      )).decrypt(passphrase);
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);
      expect(skesk.s2k is Argon2S2k, isTrue);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        'bbeda55b9aae63dac45d4f49d89dacf4af37fefc13bab2f1f8e18fb74580d8b0'.hexToBytes(),
      );
      expect(sessionKey.symmetric, SymmetricAlgorithm.aes256);

      final seipd = SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AfirtbIE3SaPO19Vq7qe5dMCcqWZbNtVMHeu5vZKBetHnnx/yveQ9brJYlzhJvGskCUJma43+iur/T1sKjE=',
      )).decrypt(sessionKey.encryptionKey, symmetric: sessionKey.symmetric);
      final literalData = seipd.packets!.elementAt(0) as LiteralDataInterface;
      expect(literalData.binary, literalText.toBytes());
    });
  });

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
