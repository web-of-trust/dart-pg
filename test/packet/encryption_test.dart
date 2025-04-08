import 'dart:convert';

import 'package:dart_pg/src/common/argon2_s2k.dart';
import 'package:dart_pg/src/common/config.dart';
import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/aead_algorithm.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/enum/symmetric_algorithm.dart';
import 'package:dart_pg/src/packet/base_packet.dart';
import 'package:dart_pg/src/packet/key/session_key.dart';
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
      expect(aepd.symmetric, SymmetricAlgorithm.aes256);
      expect(aepd.aead, AeadAlgorithm.eax);
      expect(aepd.chunkSize, 14);
      expect(aepd.iv.toHexadecimal(), 'b732379f73c4928de25facfe6517ec10');

      final decryptAepd =
          aepd.decrypt('86f1efb86952329f24acd3bfd0e5346d'.hexToBytes());
      final literalData =
          decryptAepd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt ocb', () {
      final bytes =
          '0107020e5ed2bc1e470abe8f1d644c7a6c8a567b0f7701196611a154ba9c2574cd056284a8ef68035c623d93cc708a43211bb6eaf2b27f7c18d571bcd83b20add3a08b73af15b9a098'
              .hexToBytes();

      final aepd = AeadEncryptedDataPacket.fromBytes(bytes);
      expect(aepd.symmetric, SymmetricAlgorithm.aes256);
      expect(aepd.aead, AeadAlgorithm.ocb);
      expect(aepd.chunkSize, 14);
      expect(aepd.iv.toHexadecimal(), '5ed2bc1e470abe8f1d644c7a6c8a56');

      final decryptAepd =
          aepd.decrypt('d1f01ba30e130aa7d2582c16e050ae44'.hexToBytes());
      final literalData =
          decryptAepd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });
  });

  group('Symmetrically decryption', () {
    const password = 'password';
    const literalText = "Hello, world!";

    test('Encrypted using aead eax', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'Bh4HAQsDCKWuV50fxdgr/2kiT5GZk7NQb6O1mmpzz/jF78X0HFf7VOHCJoFdeCj1+SxFTrZevgCrWYbGjm58VQ==',
      )).decrypt(password);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.aead, AeadAlgorithm.eax);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '3881bafe985412459b86c36f98cb9a5e'.hexToBytes(),
      );

      final seipd =
          SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AgcBBp/5DjsyGWTzpCkTyNzGYZMlAVIn77fq6qSfBMLmdBddSj0ibtavy5yprBIsFHDhHGPUwKskHGqTitSL+ZpambkLuoMl3mEEdUAlireVmpWtBR3alusVQx3+9fXiJVyngmFUbjOa',
      )).decrypt(sessionKey.encryptionKey);
      expect(seipd.symmetric, SymmetricAlgorithm.aes128);
      expect(seipd.aead, AeadAlgorithm.eax);

      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Encrypted using aead ocb', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'Bh0HAgsDCFaimNL142RT/8/MXBFmTtudtCWQ19xGsHJBthLDgSz/++oA8jR7JWQRI/iHrmDU/WFOCDfYGdNs',
      )).decrypt(password);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.aead, AeadAlgorithm.ocb);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '28e79ab82397d3c63de24ac217d7b791'.hexToBytes(),
      );

      final seipd =
          SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AgcCBiCmYfcx/JowMrViMyYCfjpdjbV0jr7/CwxZENCezdZB/5/ThWJ1gDW8SXVM4b8//6fa0KO4EE9RM89CpBAKg+70yhtIAaiEa/QrzafIzp1l4hLzAcvNmP3K3mlKh3rUJHMj9uhX',
      )).decrypt(sessionKey.encryptionKey);
      expect(seipd.symmetric, SymmetricAlgorithm.aes128);
      expect(seipd.aead, AeadAlgorithm.ocb);

      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Encrypted using aead gcm', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BhoHAwsDCOnTl4WyBwAI/7QufEg+9IhEV8s3Jrmz25/3duX02aQJUuJEcpiFGr//dSbfLdVUQXV5p3mf',
      )).decrypt(password);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.aead, AeadAlgorithm.gcm);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '1936fc8568980274bb900d8319360c77'.hexToBytes(),
      );

      final seipd =
          SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AgcDBvy5RJC8uYu9ydEGxgkCZpQPcuie3CG1WWsVdrEB7Q+f/G/G1lu/0k3NB5CWbm0ehaMAU3hMsdi2oGme8SFVp7KtYlhTG1dlH9d3eRL6leNdm0Ahb2mkwkjbKP9DMfFjKQc5nm/5',
      )).decrypt(sessionKey.encryptionKey);
      expect(seipd.symmetric, SymmetricAlgorithm.aes128);
      expect(seipd.aead, AeadAlgorithm.gcm);

      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('V4 SKESK Using Argon2 with AES-128', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BAcEnFL4PCf5XlDVNUQOzf8xNgEEFZ5S/K0izz+VZULLp5TvhAsR',
      )).decrypt(password);
      expect(skesk.symmetric, SymmetricAlgorithm.aes128);
      expect(skesk.s2k is Argon2S2k, isTrue);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '01fe16bbacfd1e7b78ef3b865187374f'.hexToBytes(),
      );
      expect(sessionKey.symmetric, SymmetricAlgorithm.aes128);

      final seipd =
          SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AZgYpj5gnPi7oX4MOUME6vk1FBe38okh/ibiY6UrIL+6otumcslkydOrejv0bEFN0h07OEdd8DempXiZPMU=',
      )).decrypt(sessionKey.encryptionKey, sessionKey.symmetric);
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('V4 SKESK Using Argon2 with AES-192', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BAgE4UysRxU0WRipYtyjR+FD+AEEFYcyydr2txRvP6ZqSD3fx/5naFUuVQSy8Bc=',
      )).decrypt(password);
      expect(skesk.symmetric, SymmetricAlgorithm.aes192);
      expect(skesk.s2k is Argon2S2k, isTrue);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        '27006dae68e509022ce45a14e569e91001c2955af8dfe194'.hexToBytes(),
      );
      expect(sessionKey.symmetric, SymmetricAlgorithm.aes192);

      final seipd =
          SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AdJ1Sw56PRYiKZjCvHg+2bnq02s33AJJoyBexBI4QKATFRkyez2gldJldRysLVg77Mwwfgl2n/d572WciAM=',
      )).decrypt(sessionKey.encryptionKey, sessionKey.symmetric);
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('V4 SKESK Using Argon2 with AES-256', () {
      final skesk = SymEncryptedSessionKeyPacket.fromBytes(base64.decode(
        'BAkEuHiVICBv95nGiCxCRaZifAEEFZ2fZeyrWoHQpZvVGkP2ejP+a6JJUhqRrutt2Jml3sxo/A==',
      )).decrypt(password);
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);
      expect(skesk.s2k is Argon2S2k, isTrue);

      final sessionKey = skesk.sessionKey!;
      expect(
        sessionKey.encryptionKey,
        'bbeda55b9aae63dac45d4f49d89dacf4af37fefc13bab2f1f8e18fb74580d8b0'
            .hexToBytes(),
      );
      expect(sessionKey.symmetric, SymmetricAlgorithm.aes256);

      final seipd =
          SymEncryptedIntegrityProtectedDataPacket.fromBytes(base64.decode(
        'AfirtbIE3SaPO19Vq7qe5dMCcqWZbNtVMHeu5vZKBetHnnx/yveQ9brJYlzhJvGskCUJma43+iur/T1sKjE=',
      )).decrypt(sessionKey.encryptionKey, sessionKey.symmetric);
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
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
        SymmetricAlgorithm.aes128,
      );
      final encrypt = SymEncryptedDataPacket.fromBytes(
        encrypted.data,
      );

      expect(
        () => encrypt.decrypt(
          key,
          SymmetricAlgorithm.aes128,
        ),
        throwsA(isA<Error>()),
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
        SymmetricAlgorithm.aes128,
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

  group('Password protected session key', () {
    final password = Helper.generatePassword();
    final literalText = faker.randomGenerator.string(1000);

    test('Encrypt with null session key', () {
      final skesk = SymEncryptedSessionKeyPacket.encryptSessionKey(
        password,
        symmetric: Config.preferredSymmetric,
      );
      final sessionKey = skesk.sessionKey!;
      final seipd = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        sessionKey.encryptionKey,
        PacketList([LiteralDataPacket.fromText(literalText)]),
        symmetric: sessionKey.symmetric,
      );
      expect(sessionKey.symmetric, skesk.symmetric);

      final packets = PacketList.decode(PacketList([skesk, seipd]).encode());
      final decryptSkesk = packets
          .whereType<SymEncryptedSessionKeyPacket>()
          .first
          .decrypt(password);
      final decryptSeipd = packets
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            decryptSkesk.sessionKey!.encryptionKey,
            decryptSkesk.sessionKey!.symmetric,
          );
      final literalData =
          decryptSeipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.text, literalText);
    });

    test('Encrypt with session key', () {
      final sessionKey = SessionKey.produceKey(Config.preferredSymmetric);
      final skesk = SymEncryptedSessionKeyPacket.encryptSessionKey(
        password,
        sessionKey: sessionKey,
        symmetric: SymmetricAlgorithm.aes256,
      );
      final seipd = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        sessionKey.encryptionKey,
        PacketList([LiteralDataPacket.fromText(literalText)]),
        symmetric: sessionKey.symmetric,
      );
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);

      final packets = PacketList.decode(PacketList([skesk, seipd]).encode());
      final decryptSkesk = packets
          .whereType<SymEncryptedSessionKeyPacket>()
          .first
          .decrypt(password);
      final decryptSeipd = packets
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            decryptSkesk.sessionKey!.encryptionKey,
            decryptSkesk.sessionKey!.symmetric,
          );
      final literalData =
          decryptSeipd.packets!.whereType<LiteralDataInterface>().first;
      expect(
        decryptSkesk.symmetric,
        SymmetricAlgorithm.aes256,
      );
      expect(literalData.text, literalText);
    });

    test('Aead encrypt with session key', () {
      final sessionKey = SessionKey.produceKey(Config.preferredSymmetric);
      final skesk = SymEncryptedSessionKeyPacket.encryptSessionKey(
        password,
        sessionKey: sessionKey,
        symmetric: SymmetricAlgorithm.aes256,
        aead: Config.preferredAead,
      );
      final seipd = SymEncryptedIntegrityProtectedDataPacket.encryptPackets(
        sessionKey.encryptionKey,
        PacketList([LiteralDataPacket.fromText(literalText)]),
        symmetric: sessionKey.symmetric,
        aead: Config.preferredAead,
      );
      expect(skesk.version, 6);
      expect(skesk.symmetric, SymmetricAlgorithm.aes256);
      expect(skesk.aead, Config.preferredAead);
      expect(seipd.version, 2);
      expect(seipd.symmetric, sessionKey.symmetric);
      expect(seipd.aead, Config.preferredAead);

      final packets = PacketList.decode(PacketList([skesk, seipd]).encode());
      final decryptSkesk = packets
          .whereType<SymEncryptedSessionKeyPacket>()
          .first
          .decrypt(password);
      final decryptSeipd = packets
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            decryptSkesk.sessionKey!.encryptionKey,
            decryptSkesk.sessionKey!.symmetric,
          );
      final literalData =
          decryptSeipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.text, literalText);
    });
  });

  group('Public key protected session key', () {
    const literalText = 'Hello World :)';
    final sessionKey = SessionKey.produceKey();

    test('Decrypt with RSA subkey', () {
      final subkeyData = '''
BF2lnPIBDADWML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI
DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+Uzula/6k1Dog
Df28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AObaifV7wIhEJnvqgFXDN2RXGj
LeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6G
DohBQSfZW2+LXoPZuVE/wGlQ01rh827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZY
I2e8c+paLNDdVPL6vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUn
R76UqVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48AEQEAAQAL
/RdgsLI0vko4dTNb3oCW2Y3ouIBdRx6RDNCtD0l7KUn1b6UeAKEieB3ugl0jFoNKLfFyrQ7maFfY
5yWhEuVC/aTAA+ycCDqmZvw2FSTOYTgEgodXN+ev8EmxW80Rz7VHWTvUN9FhTSTOaR2wiT47TaEZ
kRpH+9Ucbbxwc8u56RmvlulPzVSh8NItAmMDCNGJSg2pGFtz5vkC/oB2Rb54BsHk6HdH/ZdlSywJ
nkEf3PhGbO5TbpobmfJl3MIVHPSUCITpKTvsK3g8rBBZAHLCm5ED91A1LANYBcfaWzM09La9aGat
muEAbcUoR8z/6Yeyi6TfuqrY5LN8Qf8o04Ghpra8DPLUntMA9UcF0vv9aAR6V050O033jhlALuCg
qDkC7+hC6Slm0QS1roj8DHWxqb1RQCzvPpLygIPf6/v58szNhkB2PidyYeScT4iZx31zWYyCi2xW
yD3UijciQbms11vMSGv/5hBzCOTnL7GQSnJQCKey184xIylyMB8A3E5/aQYA6XTikxzrSdyVCsdK
1lbAx+sKuoilfxU1UmOY5czfqbjhLLJBdS38Z/SbCYoQFTt8jbKekb5CrcjZRWs2glSrQwJpI6Ie
tFzcXDUaq4Ap8HaW4HRz+r/4b2WOeGWiY8+i9nvLpzRJGC8Q7fHJgMhj4B9l4C+4IhyKfY67EGkt
/NYJ2MDV+sBNWhIpILWPdZ6iY8D5YmxfWr0smEKDLRKjP9VI04wdinQ/zIrSuXz9Fab7l6TWGXnZ
squFDjMHZIjTBgDq35jnk9KJYC60zE+R/ewp92MW5Nd7lxzbv2VGWTXvLPkLbi31JSgCbSxFLrTd
905VkGOdthVdJte0vm/NMSYm98mVSbXlbq64eR0lhwDPs4IUALwnrIOQi12tnTTJEwpmSoAgb3wy
2bmW4xcJ8AiOrvzYTmPXoCrlH0gP43v0V2k/JuVcS2DMcKkFygKcw/O379LSz5VSBL4xLGn/fdrR
RBUjT3BtZf46XeQFV8OpCrn/OVJCbWEdcdjJEA66mNUF/1zMNNJLfMvZDGVK3tfWggK3JqK/oQ4U
SRNxreECaw/c/2yAhEsOG+M9g24A/18/SF7AP6/XCojNYeUDLV77ocn1XjNNXp4cTBmzh94I6qhj
SsrMdFDgxhMK+gFfYQHfEVlzHISS2hMSvSeUkWsEoOu9TmwFNuEnWLzEPWeJAENvtUXlGc396IEj
EWbTE/ndfIE+i/dP8vgD2SGqAKyz4XmyABqt/Ry5idusd89FgIK6QNZDbI1xF5KImRjyyiBqHt4a
''';
      final packetListData = '''
wcDMA3wvqk35PDeyAQv/UXZYWGSxURvRk1E/ONY6EjQGdTEVgcpFzSpxU+KFss8eByzz4gQSG2mD
NY19lplr395XIwZOjkW0SvZZyZ5fWoL8cCZmtsK4wzwTAv6pILHEsAu0lTX1SiS40sBPiN/G+gxH
5jdPWqS44glBb5TqtaXi4MUk/XW/TQlXwk7btk+GWDwn9k75vsSosKwdIiLeY4+opqZBzwrSq47d
yux7J5VbNsGLmUELG7vvYJPopv61c1k/V2OsuHhLTtYmdH0zwK5yaHBUlMyCzoR0RNMoNqPNY5aW
mcall4wG29sh0VPSc/SWmiWfJps6CC1m46enpYSRf6VtosrJfyoR/xyL6pS6SSf3AYlSeJIfRYrN
WUlZSqHRuD/11Hh9WQgbyikT0/HWN6MKUYaC5ozOr4w0KIsCOk2vdOU6ZCbwcZlm+ZJFfE8T1PGu
+osbpZiwXzhbxUX0vcK0IR9he0cxoLcsl/sp+ff0mvtD84oKHZy+WmBDORlQeGLOB3Bi1FGD8n3O
0j8B5NnjKZXdIKpjGUT2T6o+xPsJIufIVinzhlMReyqQ7d5gVNKAsuFQKzAcBv/hOIQnAabSiF4r
2QYTOt7WX7s=
''';

      final subkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(subkey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);

      final packetList = PacketList.decode(
        base64.decode(
          packetListData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final pkesk = packetList
          .whereType<PublicKeyEncryptedSessionKeyPacket>()
          .first
          .decrypt(subkey);
      final sessionKey = pkesk.sessionKey!;
      final seipd = packetList
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            sessionKey.encryptionKey,
            sessionKey.symmetric,
          );
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt with ElGamal subkey', () {
      final subkeyData = '''
BF3+CmgQDADZhdKTM3ms3XpXnQke83FgaIBtP1g1qhqpCfg50WiPS0kjiMC0OJz2vh59nusbBLzg
I//Y1VMhKfIWYbqMcIY+lWbseHjl52rqW6AaJ0TH4NgVt7vhyVeJt0k/NnxvNhMd0587KXmfpDxr
wBqc/l5cVB+p0rL8vs8kxojHXAi5V3koM0UjREWs5Jpj/XU9LhEoyXZkeJC/pes1u6UKoFYn7dFI
P49Kkd1kb+1bNfdPYtA0JpcGzYgeMNOvdWJwn43dNhxoeuXfmAEhA8LdzT0C0O+7akXOKWrfhXJ8
MTBqvPgWZYx7MNuQx/ejIMZHl+Iaf7hG976ILH+NCGiKkhidd9GIuA/WteHiQbXLyfiQ4n8P12q9
+4dq6ybUM65tnozRyyN+1m3rU2a/+Ly3JCh4TeO27w+cxMWkaeHyTQaJVMbMbDpXduVd32MA33UV
NH5/KXMVczVi5asVjuKDSojJDV1QwX8izZNl1t+AI0L3balCabV0SFhlfnBEUj1my1sMAIfl/H7J
QB1nxW7/bNZMfHBYn9fqAZMupr0KZ8OrlQOpgUXO5bA3gcn6vI65qTUIbBIolQFIDvkcTFu/Sdpa
D6y7L6kQO8XRUAs9T1VSRJC0fJHXRg7YVY57cAS2ltgNHCl2vVnARtvcvogZDmL/gI0dsna7fJR5
ewM0C+ulVIRwiMDTVE8I4qZ/nxINmnjIN0/EaEzzDprXz591CvbZ/ZwnTGB8+VvMVs74VSwSAq+f
pBMuFtpjDjOzut1AN6NYdXzaE/gr6tv0XCSdh1X26jibvsyAaVT7jK8mcYRhovePCMjdsf1qig06
Xpdu9UDM3OiZiZpM7uanrEUC7jfK4bJ30r7UTiTsJBNE7FNn5F21CNX3mFKwSYyDv3adC8NIFbjH
B85Dul/eQLuv1+by72cGUQ3XYextDxi+7H+V3mrlFoiUPX2PN9VHr6EnNuPZmdTJCziSwB8gdPNN
0u21HFL2VNFORXHa9tSehIHLpNgXWZ/qdE+lKbWuJnGeRHj4FAv+MQaafW0uHF+N8MDm8UWPvf4V
d0UJ0UpIjRWl2hTV+BHkNfvZlBRhhQIphNiKRe/Wap0f/lW2Gm2uS0KgByjjNXEzTiwrte2GX65M
6F6Lz8N31kt1Iig1xGOuv+6HmxTNR8gL2K5PdJeJn8PTJWrRS7+BY8Hdkgb+wVpzE5cCvpFiG/P0
yqfBdLWxVPlPI7dchDkmx4iAhHJX9J/gX/hC6L3AzPNJqNPAKy20wYp/ruTbbwBolW/4ikWij460
JrvBsm6Sp81A3ebaiN9XkJygLOyhGyhMieGulCYz6AahAFcECtPXGTcordV1mJth8yjF4gZfDQyg
0nMW4Yr49yeFXcRMUw1yzN3Q9v2zzqDuFi2lGYTXYmVqLYzM9KbLO2WxE/21xnBjLsl09l/FdA/b
hdZq3t4/apbFOeQQ/j/AphvzWbsJnhG9Q7+d3VoDlz0gFiSduCYIAAq8dUOJNjrUTkZsL1pOIjhY
jCMi2uiKS6RQkT6nvuumPF/D/VTnUGeZAAD+KHmMi2GfZkSvVig6xSzwIGHKVOxFkrpVLhkIStzK
Xa0PYg==
''';
      final packetListData = '''
wcJOA92wTJQbq0qsEAv/RmVvuYpXwWuEKi8FGkD/6brX96NaAYVY9NM6tzj2Cgk4QxPSlUQJQvGD
wP48EWfOGvXXJZxW6vwLnW9pdXKBBIfrYkU+3vjvrvUSqucP6JZpMIXcQD15heD98gpdA7Tws1fn
iTgVV0L1pRj0BBimQMahlMAXMV2HirUzG9edLl+/6w/JaFnuHquOwdP6bfqmnUdmG/x9z6hntMHY
b6E+eUM7LKhI+OyThnys+h/A/3BbdDsynVpYi7PUxvfOathoTYHEx6AmaA7rRtuPdAADKX04Du9v
73jdvxfiKX2lgxlIUxRCofgI+kohMsUqGKFROeJLunIXa9iJni2X0AXZO+7rWhZTC9ZPYlhP0K23
TMcr4eTUqaQgaNfHhac15uF5J7mKGZsq5NguLYHf0ovwXtcwXq1TeZQTSHj3o1P+QvtcGaZF5FDF
rcyN2Z0oQkK4wdZl/z1wevqjOW6Fpy9kq2RF2zhAa9v3zXSeRr+ic8wOZAD8XPn1lP0q46YB/Oaw
C/9lsHZuduT0YBeG3l0cOEAPF4y78tA32wA3RcwmqDKk/Lp2u7tXejORCEqRqzLQ7rSlCcfivBoD
QczTuCM071hM8DQ33ENpGfW3w3/uqHRXDjaOKSld0bcPgmiHpLbOzAwyxgHM3SqwAZofj+Sw36/K
dkFpURmnQY89m/ELChBbfUWFbnXSsLOCHq0dj3FnDGTmNqQLCT/qte62YWVkgVghSSH6OhTmHZ81
XUQI+RLHt3lvhF3YuUvdOd+/1WstKXwtTEMpmailGEyhbTnYeqV5rPo1NhaYvI2ieYzU6M3pz7hU
4ebMatDirZTy/o19unwJCAXQuhfVTblWHp8cvPB0BlkImhHr94AGDTAUwZCzP6+aNmWpoX3fBlDB
D7jv3XI21vufPF0FgXAvo/TOIZya+EmIY106HP2ySgaLCG++YGSU/DBbXIA9H5aGpA+MPiZmw8HO
sHn9xYLcI33N28qWQkPjvNkvYyMjuGb94ReXiN+SvuaMUFQpXjJGqw3PALnSQwGkJ4dgWQKW+gP3
heUWSSwsi+sdLtKcnQQfj/RDqmhO9tmfk8sRTu3Myp9tYJLnjngOxsNEMoRRgo7eBSLVjUQlQu8=
''';

      final subkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(subkey.keyAlgorithm, KeyAlgorithm.elgamal);

      final packetList = PacketList.decode(
        base64.decode(
          packetListData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final pkesk = packetList
          .whereType<PublicKeyEncryptedSessionKeyPacket>()
          .first
          .decrypt(subkey);
      final sessionKey = pkesk.sessionKey!;
      final seipd = packetList
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            sessionKey.encryptionKey,
            sessionKey.symmetric,
          );
      final comPacket = seipd.packets!.whereType<CompressedDataPacket>().first;
      final literalData =
          comPacket.packets.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt with ECDH NIST P-384 subkey', () {
      final subkeyData = '''
BGc/+YkSBSuBBAAiAwME6+LPwcbdvoEdxPA2L002pKXp8Nt7PxIsjUegQRw2bTQXMlu5zplsUNpr
WJZ1W/iqLhmEH8eLONxcuzVEQMb3dCImxBzmL3Y5HxGGti81EsU7JBIZxHKhl85RY78HdHgCAwEJ
CQABf19UJNkpedSjrDT3bwSSzOlI8/uyJzKkqF5z26O2i+UbQ/VYIK78pSWB5/YNCfpTHRn5
''';
      final packetListData = '''
wY4DWimQzmvWOyASAwME8gf7ALFjHdnr+1HOfeaBR7LJ3cSQBXB+vSd1d1Tt7nk6aKvCTrkDg8FN
n4V8crQpq5O47id1cWX5RaxxPoqN0wVeqFcDwfRKjAkR6hheaUnnAkrkN873nH6QkQTKJm7bICWq
PXVtziQ8IyqoGshWNSwpWcPZl9KW2mUBGVIpOtCg0j8BYZTkYDl0D/a62/c1QUyqjpXqgGhzXvuS
23BdpGx/IkjjyOVV3mSvG54iZDtqtfYL5WWys9Euw7n2zOWb8E4=
''';

      final subkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);

      final packetList = PacketList.decode(
        base64.decode(
          packetListData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final pkesk = packetList
          .whereType<PublicKeyEncryptedSessionKeyPacket>()
          .first
          .decrypt(subkey);
      final sessionKey = pkesk.sessionKey!;
      final seipd = packetList
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            sessionKey.encryptionKey,
            sessionKey.symmetric,
          );
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt with ECDH Brainpool P-256 subkey', () {
      final subkeyData = '''
BGc/+dASCSskAwMCCAEBBwIDBGuDRKYwfAtThNOAM51Is4J1BYPN6qZCTN0c9ldSQzGSVO0lI/BV
2JJsuQqI0Pne08Y7og4bhyv9S+D+wcU8sv0DAQgHAAEAoE4oBDyVgNFV3b7pSIJe+mrkuJYxel3E
JezusZoe4R0RBg==
''';
      final packetListData = '''
wW4DZbU70a/wXgYSAgMEho+Zrglsg+H4OtMqAI96cGR9lPCWr3q5DhnCAM2kIGofREOFwOm3BIcZ
1QPGtziET3wRmVxF7bSu3i7Sxgq/TSBdQdIy4GS4UpC2LP+bwgyXRgJBMFWa0EL86TcwcAwn49I/
AXzl+1DZczLIfN+EPS+dkDwlf4BiX82RZby5klmHzg8r3VqtMkyAwwoGgxn1JXzoWKUINsFBOG6J
dJb40maS
''';

      final subkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);

      final packetList = PacketList.decode(
        base64.decode(
          packetListData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final pkesk = packetList
          .whereType<PublicKeyEncryptedSessionKeyPacket>()
          .first
          .decrypt(subkey);
      final sessionKey = pkesk.sessionKey!;
      final seipd = packetList
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            sessionKey.encryptionKey,
            sessionKey.symmetric,
          );
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt with ECDH x25519 subkey', () {
      final subkeyData = '''
BFxHBOkSCisGAQQBl1UBBQEBB0BC/wYhratJPOCptcKkMNgyIpFWK0KzLbTfHewT356+IgMBCAcA
AP9/8RTxulNe64U7qvtO4JhL2hWCn8UQerIAGIlukzE6UBCu
''';
      final packetListData = '''
wV4DR2b2udXyHrYSAQdAbADLqbFjAj5vsaZrsEQyPE0f9MkFeEopzPJ5DhpBKVow0JijpGDNhQ53
UuPfdlmTJQxTfOasai86MJvGTZbaiZq2MYBHn1w1UkAibx5RUX3r0j8B0WUc//ZJCcpU440qFbrD
SdJraH1GfEeeMdV9t8623Gu3xkQ4hXf+figKNUWdq+kwHGqbQQNoeai1TYYNCuY=
''';

      final subkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);

      final packetList = PacketList.decode(
        base64.decode(
          packetListData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final pkesk = packetList
          .whereType<PublicKeyEncryptedSessionKeyPacket>()
          .first
          .decrypt(subkey);
      final sessionKey = pkesk.sessionKey!;
      final seipd = packetList
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            sessionKey.encryptionKey,
            sessionKey.symmetric,
          );
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt with x25519 rfc9580 subkey', () {
      final subkeyData = '''
BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u
/tVY6a//1q0NWC1X+yui3O24
''';
      final packetListData = '''
wW0GIQYSyD8ecG9jCP4VGkF3Q6HwM3kOk+mXhIjR2zeNqZMIhRmYQIdvyFFkbvQontVWA5ukwSV2
G16sUGyAgCirPA+1ISgjo8WL43phtu5TkL7Z59/eXc9IogZy/V+V+SkcSc1vF0WQ2F8kX/Az0loC
CQIM3eSIHALVilESDk12PS37M9JkaseDvMWVtfEOE9b1lG3aYJXruqm0GZAV8DoyM/HCQBTOGa8m
UQi6XlKOsfRPH6ozJjwLn7nPdfz5pHPtR0QljShJqeM=
''';

      final subkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(subkey.keyAlgorithm, KeyAlgorithm.x25519);

      final packetList = PacketList.decode(
        base64.decode(
          packetListData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final pkesk = packetList
          .whereType<PublicKeyEncryptedSessionKeyPacket>()
          .first
          .decrypt(subkey);
      final sessionKey = pkesk.sessionKey!;
      final seipd = packetList
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            sessionKey.encryptionKey,
            sessionKey.symmetric,
          );
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, literalText.toBytes());
    });

    test('Decrypt with x448 rfc9580 subkey', () {
      final subkeyData = '''
BmUai2IaAAAAON1puvWiEA6dtJRSRWG1Qz8tV2diAMuGZqNhnU3tNZjR+oSkyTYsujbXrkc6aF11
E95MHVNZu7AHAHyUpzdzMVTNhwCC9nTxPlJRQeN8iGN4l5jjJ3Q5kN/M/DW9t6AJzu33htP5cagh
BsL8GXscLICI
''';
      final packetListData = '''
wXUGIQZh4qTsn8glFgGNbIdCTl8gH2OtkI/PAGCQ0gi9s9k/rhrDhXo7kUKDJ39FfNp3kmAaM24C
e3bcYXwLy0gF2i6rxfL20D+g3cxv0i3CuXQCgcbojTN/8KY8ExiVXdfo+OWIZ5XndtyMpJW28BiL
Hru+n9bSwM8CBwMMENh7cT8lILXteh885FrUUD1QJMtD7xJUn2y78cVGgFSIkLbvFPDerB37xuht
MRkykuWgbUoJH/kcgBPdeCoYzJmfLV9FyATv0/AYq0yWpQ0VUfNLTFyeHIGxz7NHvrzJSrOy1Gm3
1PXqWvb4sBROjnOXoAk12JdPudz3l1QZT/DX947f4h6hwkVv7RRT0oOS2pMaz/mekRuD6utUcpsj
FQ/MEDphnhOsB4RH0il8YPVc9DCnf3GhSs66h+Z699MXHBaUmdtiN1IgoEgLfb/900U2TfI6dvrv
C56WIMA8EA1COvLGc9Ge4owW0UE8jIuqWLzA2nVg5belbzhNnOEh9b1cOcDUh8CfBuXqHEi/ANMU
OMmaIGfcHfQFVu5v/UMcLxcH/fSVF6DvtOxEoUxASWBSmp6yC4A778BFuDFXb+/T8FjuJBaUj9rC
SkYqt1TYVKG1XZPI4OdIvGtneo+vH/CqF6bxlLWU6oskZ5SE+xJblmmO01ObM9JRi9D8jZnXedTH
ExAnXHXIb8I=
''';

      final subkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(subkey.keyAlgorithm, KeyAlgorithm.x448);

      final packetList = PacketList.decode(
        base64.decode(
          packetListData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final pkesk = packetList
          .whereType<PublicKeyEncryptedSessionKeyPacket>()
          .first
          .decrypt(subkey);
      final sessionKey = pkesk.sessionKey!;
      final seipd = packetList
          .whereType<SymEncryptedIntegrityProtectedDataPacket>()
          .first
          .decrypt(
            sessionKey.encryptionKey,
            sessionKey.symmetric,
          );
      final literalData =
          seipd.packets!.whereType<LiteralDataInterface>().first;
      expect(literalData.binary, 'Hello there'.toBytes());
    });

    test('Encrypt session key with RSA subkey', () {
      final publicSubkeyData = '''
BF2lnPIBDADWML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI
DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+Uzula/6k1Dog
Df28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AObaifV7wIhEJnvqgFXDN2RXGj
LeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6G
DohBQSfZW2+LXoPZuVE/wGlQ01rh827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZY
I2e8c+paLNDdVPL6vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUn
R76UqVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48AEQEAAQ==
''';
      final secretSubkeyData = '''
BF2lnPIBDADWML9cbGMrp12CtF9b2P6z9TTT74S8iyBOzaSvdGDQY/sUtZXRg21HWamXnn9sSXvI
DEINOQ6A9QxdxoqWdCHrOuW3ofneYXoG+zeKc4dC86wa1TR2q9vW+RMXSO4uImA+Uzula/6k1Dog
Df28qhCxMwG/i/m9g1c/0aApuDyKdQ1PXsHHNlgd/Dn6rrd5y2AObaifV7wIhEJnvqgFXDN2RXGj
LeCOHV4Q2WTYPg/S4k1nMXVDwZXrvIsA0YwIMgIT86Rafp1qKlgPNbiIlC1g9RY/iFaGN2b4Ir6G
DohBQSfZW2+LXoPZuVE/wGlQ01rh827KVZW4lXvqsge+wtnWlszcselGATyzqOK9LdHPdZGzROZY
I2e8c+paLNDdVPL6vdRBUnkCaEkOtl1mr2JpQi5nTU+gTX4IeInC7E+1a9UDF/Y85ybUz8XV8rUn
R76UqVC7KidNepdHbZjjXCt8/Zo+Tec9JNbYNQB/e9ExmDntmlHEsSEQzFwzj8sxH48AEQEAAQAL
/RdgsLI0vko4dTNb3oCW2Y3ouIBdRx6RDNCtD0l7KUn1b6UeAKEieB3ugl0jFoNKLfFyrQ7maFfY
5yWhEuVC/aTAA+ycCDqmZvw2FSTOYTgEgodXN+ev8EmxW80Rz7VHWTvUN9FhTSTOaR2wiT47TaEZ
kRpH+9Ucbbxwc8u56RmvlulPzVSh8NItAmMDCNGJSg2pGFtz5vkC/oB2Rb54BsHk6HdH/ZdlSywJ
nkEf3PhGbO5TbpobmfJl3MIVHPSUCITpKTvsK3g8rBBZAHLCm5ED91A1LANYBcfaWzM09La9aGat
muEAbcUoR8z/6Yeyi6TfuqrY5LN8Qf8o04Ghpra8DPLUntMA9UcF0vv9aAR6V050O033jhlALuCg
qDkC7+hC6Slm0QS1roj8DHWxqb1RQCzvPpLygIPf6/v58szNhkB2PidyYeScT4iZx31zWYyCi2xW
yD3UijciQbms11vMSGv/5hBzCOTnL7GQSnJQCKey184xIylyMB8A3E5/aQYA6XTikxzrSdyVCsdK
1lbAx+sKuoilfxU1UmOY5czfqbjhLLJBdS38Z/SbCYoQFTt8jbKekb5CrcjZRWs2glSrQwJpI6Ie
tFzcXDUaq4Ap8HaW4HRz+r/4b2WOeGWiY8+i9nvLpzRJGC8Q7fHJgMhj4B9l4C+4IhyKfY67EGkt
/NYJ2MDV+sBNWhIpILWPdZ6iY8D5YmxfWr0smEKDLRKjP9VI04wdinQ/zIrSuXz9Fab7l6TWGXnZ
squFDjMHZIjTBgDq35jnk9KJYC60zE+R/ewp92MW5Nd7lxzbv2VGWTXvLPkLbi31JSgCbSxFLrTd
905VkGOdthVdJte0vm/NMSYm98mVSbXlbq64eR0lhwDPs4IUALwnrIOQi12tnTTJEwpmSoAgb3wy
2bmW4xcJ8AiOrvzYTmPXoCrlH0gP43v0V2k/JuVcS2DMcKkFygKcw/O379LSz5VSBL4xLGn/fdrR
RBUjT3BtZf46XeQFV8OpCrn/OVJCbWEdcdjJEA66mNUF/1zMNNJLfMvZDGVK3tfWggK3JqK/oQ4U
SRNxreECaw/c/2yAhEsOG+M9g24A/18/SF7AP6/XCojNYeUDLV77ocn1XjNNXp4cTBmzh94I6qhj
SsrMdFDgxhMK+gFfYQHfEVlzHISS2hMSvSeUkWsEoOu9TmwFNuEnWLzEPWeJAENvtUXlGc396IEj
EWbTE/ndfIE+i/dP8vgD2SGqAKyz4XmyABqt/Ry5idusd89FgIK6QNZDbI1xF5KImRjyyiBqHt4a
''';

      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          publicSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          secretSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(publicSubkey.fingerprint, secretSubkey.fingerprint);

      final encryptedPkesk =
          PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
        publicSubkey,
        sessionKey,
      );
      final decryptedPkesk = PublicKeyEncryptedSessionKeyPacket.fromBytes(
        encryptedPkesk.data,
      ).decrypt(secretSubkey);
      expect(
          decryptedPkesk.sessionKey!.encryptionKey, sessionKey.encryptionKey);
    });

    test('Encrypt session key with ECDH NIST P-384 subkey', () {
      final publicSubkeyData = '''
BGc/+YkSBSuBBAAiAwME6+LPwcbdvoEdxPA2L002pKXp8Nt7PxIsjUegQRw2bTQXMlu5zplsUNpr
WJZ1W/iqLhmEH8eLONxcuzVEQMb3dCImxBzmL3Y5HxGGti81EsU7JBIZxHKhl85RY78HdHgCAwEJ
CQ==
''';
      final secretSubkeyData = '''
BGc/+YkSBSuBBAAiAwME6+LPwcbdvoEdxPA2L002pKXp8Nt7PxIsjUegQRw2bTQXMlu5zplsUNpr
WJZ1W/iqLhmEH8eLONxcuzVEQMb3dCImxBzmL3Y5HxGGti81EsU7JBIZxHKhl85RY78HdHgCAwEJ
CQABf19UJNkpedSjrDT3bwSSzOlI8/uyJzKkqF5z26O2i+UbQ/VYIK78pSWB5/YNCfpTHRn5
''';

      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          publicSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          secretSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(publicSubkey.fingerprint, secretSubkey.fingerprint);

      final encryptedPkesk =
          PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
        publicSubkey,
        sessionKey,
      );
      final decryptedPkesk = PublicKeyEncryptedSessionKeyPacket.fromBytes(
        encryptedPkesk.data,
      ).decrypt(secretSubkey);
      expect(
          decryptedPkesk.sessionKey!.encryptionKey, sessionKey.encryptionKey);
    });

    test('Encrypt session key with ECDH Brainpool P-256  subkey', () {
      final publicSubkeyData = '''
BGc/+dASCSskAwMCCAEBBwIDBGuDRKYwfAtThNOAM51Is4J1BYPN6qZCTN0c9ldSQzGSVO0lI/BV
2JJsuQqI0Pne08Y7og4bhyv9S+D+wcU8sv0DAQgH
''';
      final secretSubkeyData = '''
BGc/+dASCSskAwMCCAEBBwIDBGuDRKYwfAtThNOAM51Is4J1BYPN6qZCTN0c9ldSQzGSVO0lI/BV
2JJsuQqI0Pne08Y7og4bhyv9S+D+wcU8sv0DAQgHAAEAoE4oBDyVgNFV3b7pSIJe+mrkuJYxel3E
JezusZoe4R0RBg==
''';

      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          publicSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          secretSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(publicSubkey.fingerprint, secretSubkey.fingerprint);

      final encryptedPkesk =
          PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
        publicSubkey,
        sessionKey,
      );
      final decryptedPkesk = PublicKeyEncryptedSessionKeyPacket.fromBytes(
        encryptedPkesk.data,
      ).decrypt(secretSubkey);
      expect(
          decryptedPkesk.sessionKey!.encryptionKey, sessionKey.encryptionKey);
    });

    test('Encrypt session key with ECDH x25519 subkey', () {
      final publicSubkeyData = '''
BFxHBOkSCisGAQQBl1UBBQEBB0BC/wYhratJPOCptcKkMNgyIpFWK0KzLbTfHewT356+IgMBCAc=
''';
      final secretSubkeyData = '''
BFxHBOkSCisGAQQBl1UBBQEBB0BC/wYhratJPOCptcKkMNgyIpFWK0KzLbTfHewT356+IgMBCAcA
AP9/8RTxulNe64U7qvtO4JhL2hWCn8UQerIAGIlukzE6UBCu
''';

      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          publicSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          secretSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(publicSubkey.fingerprint, secretSubkey.fingerprint);

      final encryptedPkesk =
          PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
        publicSubkey,
        sessionKey,
      );
      final decryptedPkesk = PublicKeyEncryptedSessionKeyPacket.fromBytes(
        encryptedPkesk.data,
      ).decrypt(secretSubkey);
      expect(
          decryptedPkesk.sessionKey!.encryptionKey, sessionKey.encryptionKey);
    });

    test('Encrypt session key with x25519 rfc9580 subkey', () {
      final publicSubkeyData = '''
BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1
''';
      final secretSubkeyData = '''
BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1AE1gCk95TUR3XFeibg/u
/tVY6a//1q0NWC1X+yui3O24
''';

      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          publicSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          secretSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.x25519);
      expect(publicSubkey.fingerprint, secretSubkey.fingerprint);

      final encryptedPkesk =
          PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
        publicSubkey,
        sessionKey,
      );
      final decryptedPkesk = PublicKeyEncryptedSessionKeyPacket.fromBytes(
        encryptedPkesk.data,
      ).decrypt(secretSubkey);
      expect(
          decryptedPkesk.sessionKey!.encryptionKey, sessionKey.encryptionKey);
    });

    test('Encrypt session key with x448 rfc9580 subkey', () {
      final publicSubkeyData = '''
BmUai2IaAAAAON1puvWiEA6dtJRSRWG1Qz8tV2diAMuGZqNhnU3tNZjR+oSkyTYsujbXrkc6aF11
E95MHVNZu7AH
''';
      final secretSubkeyData = '''
BmUai2IaAAAAON1puvWiEA6dtJRSRWG1Qz8tV2diAMuGZqNhnU3tNZjR+oSkyTYsujbXrkc6aF11
E95MHVNZu7AHAHyUpzdzMVTNhwCC9nTxPlJRQeN8iGN4l5jjJ3Q5kN/M/DW9t6AJzu33htP5cagh
BsL8GXscLICI
''';

      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          publicSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          secretSubkeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.x448);
      expect(publicSubkey.fingerprint, secretSubkey.fingerprint);

      final encryptedPkesk =
          PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
        publicSubkey,
        sessionKey,
      );
      final decryptedPkesk = PublicKeyEncryptedSessionKeyPacket.fromBytes(
        encryptedPkesk.data,
      ).decrypt(secretSubkey);
      expect(
          decryptedPkesk.sessionKey!.encryptionKey, sessionKey.encryptionKey);
    });
  });
}
