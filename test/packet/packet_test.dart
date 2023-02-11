import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/src/armor/armor.dart';
import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/key/dsa_public_params.dart';
import 'package:dart_pg/src/key/dsa_secret_params.dart';
import 'package:dart_pg/src/key/ec_secret_params.dart';
import 'package:dart_pg/src/key/ecdh_public_params.dart';
import 'package:dart_pg/src/key/ecdsa_public_params.dart';
import 'package:dart_pg/src/key/elgamal_public_params.dart';
import 'package:dart_pg/src/key/elgamal_secret_params.dart';
import 'package:dart_pg/src/key/rsa_public_params.dart';
import 'package:dart_pg/src/key/rsa_secret_params.dart';
import 'package:dart_pg/src/packet/image_attribute.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/public_key.dart';
import 'package:dart_pg/src/packet/public_subkey.dart';
import 'package:dart_pg/src/packet/secret_key.dart';
import 'package:dart_pg/src/packet/secret_subkey.dart';
import 'package:dart_pg/src/packet/user_attribute.dart';
import 'package:dart_pg/src/packet/user_attribute_subpacket.dart';
import 'package:dart_pg/src/packet/user_id.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../test_data.dart';

void main() {
  group('user packet tests', (() {
    final faker = Faker();
    test('user id test', (() {
      final name = faker.person.name();
      final email = faker.internet.email();
      final comment = faker.lorem.words(3).join(' ');

      final userId = UserIDPacket([name, '($comment)', email].join(' '));
      expect(userId.name, name);
      expect(userId.email, email);
      expect(userId.comment, comment);

      final cloneUserId = UserIDPacket.fromPacketData(userId.toPacketData());
      expect(userId.name, cloneUserId.name);
      expect(userId.email, cloneUserId.email);
      expect(userId.comment, cloneUserId.comment);
    }));

    test('user attribute test', (() {
      final imageData = Uint8List.fromList(faker.randomGenerator.numbers(255, 100));
      final subpacketType = faker.randomGenerator.integer(100);
      final subpacketData = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final userAttr = UserAttributePacket.fromPacketData(UserAttributePacket([
        ImageAttributeSubpacket.fromImageData(imageData),
        UserAttributeSubpacket(subpacketType, subpacketData),
      ]).toPacketData());
      final imageAttr = userAttr.attributes[0] as ImageAttributeSubpacket;
      final subpacket = userAttr.attributes[1];

      expect(imageAttr.version, 0x01);
      expect(imageAttr.encoding, ImageAttributeSubpacket.jpeg);
      expect(imageAttr.imageData, imageData);

      expect(subpacket.type, subpacketType);
      expect(subpacket.data, subpacketData);
    }));
  }));

  group('public key packet tests', () {
    test('rsa test', () {
      final deArmor = Armor.decode(rsaPublicKey);
      expect(deArmor['type'], ArmorType.publicKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.publicKey) {
          final key = packet as PublicKeyPacket;
          expect(key.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
          expect(key.algorithm, KeyAlgorithm.rsaEncryptSign);
        }
        if (packet.tag == PacketTag.publicSubkey) {
          final subkey = packet as PublicSubkeyPacket;
          expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
          expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
        }
        if (packet.tag == PacketTag.userID) {
          final userID = packet as UserIDPacket;
          expect(userID.name, 'rsa pgp key');
          expect(userID.email, 'test@dummy.com');
        }
      }
    });

    test('dsa elgamal test', () {
      final deArmor = Armor.decode(dsaPublicKey);
      expect(deArmor['type'], ArmorType.publicKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.publicKey) {
          final key = packet as PublicKeyPacket;
          expect(key.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
          expect(key.algorithm, KeyAlgorithm.dsa);
        }
        if (packet.tag == PacketTag.publicSubkey) {
          final subkey = packet as PublicSubkeyPacket;
          expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
          expect(subkey.algorithm, KeyAlgorithm.elgamal);
        }
        if (packet.tag == PacketTag.userID) {
          final userID = packet as UserIDPacket;
          expect(userID.name, 'dsa elgamal pgp key');
          expect(userID.email, 'test@dummy.com');
        }
      }
    });

    test('ecc test', () {
      final deArmor = Armor.decode(eccPublicKey);
      expect(deArmor['type'], ArmorType.publicKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.publicKey) {
          final key = packet as PublicKeyPacket;
          expect(key.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
          expect(key.algorithm, KeyAlgorithm.ecdsa);
        }
        if (packet.tag == PacketTag.publicSubkey) {
          final subkey = packet as PublicSubkeyPacket;
          expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
          expect(subkey.algorithm, KeyAlgorithm.ecdh);
        }
        if (packet.tag == PacketTag.userID) {
          final userID = packet as UserIDPacket;
          expect(userID.name, 'ecc pgp key');
          expect(userID.email, 'test@dummy.com');
        }
      }
    });
  });

  group('secret key packet tests', () {
    test('rsa test', (() {
      final deArmor = Armor.decode(rsaPrivateKey);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as RSAPublicParams;
          final secretParams = key.decrypt(passphrase).secretParams as RSASecretParams;

          expect(key.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
          expect(key.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP.modInverse(secretParams.primeQ));
          expect(publicParams.modulus, secretParams.modulus);
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as RSAPublicParams;
          final secretParams = subkey.decrypt(passphrase).secretParams as RSASecretParams;

          expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
          expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP.modInverse(secretParams.primeQ));
          expect(publicParams.modulus, secretParams.modulus);
        }
      }
    }));

    test('dsa elgamal test', () {
      final deArmor = Armor.decode(dsaPrivateKey);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as DSAPublicParams;
          final secretParams = key.decrypt(passphrase).secretParams as DSASecretParams;

          expect(key.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
          expect(key.algorithm, KeyAlgorithm.dsa);
          expect(publicParams.publicExponent,
              publicParams.groupGenerator.modPow(secretParams.secretExponent, publicParams.primeP));
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as ElGamalPublicParams;
          final secretParams = subkey.decrypt(passphrase).secretParams as ElGamalSecretParams;

          expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
          expect(subkey.algorithm, KeyAlgorithm.elgamal);
          expect(publicParams.publicExponent,
              publicParams.groupGenerator.modPow(secretParams.secretExponent, publicParams.primeP));
        }
      }
    });

    test('ecc test', () {
      final deArmor = Armor.decode(eccPrivateKey);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as ECDSAPublicParams;
          final secretParams = key.decrypt(passphrase).secretParams as ECSecretParams;

          expect(key.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
          expect(key.algorithm, KeyAlgorithm.ecdsa);
          expect(publicParams.publicKey.Q, publicParams.publicKey.parameters!.G * secretParams.d);
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as ECDHPublicParams;
          final secretParams = subkey.decrypt(passphrase).secretParams as ECSecretParams;

          expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
          expect(subkey.algorithm, KeyAlgorithm.ecdh);
          expect(publicParams.publicKey.Q, publicParams.publicKey.parameters!.G * secretParams.d);
        }
      }
    });

    test('encrypt test', (() {
      final deArmor = Armor.decode(privateKeyWithoutPassphase);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as RSAPublicParams;
          final secretParams = key.secretParams as RSASecretParams;

          expect(key.fingerprint, '93456c517e3eddb679bb510c2213de9391374950');
          expect(key.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP.modInverse(secretParams.primeQ));
          expect(publicParams.modulus, secretParams.modulus);

          expect(key.isDecrypted, true);
          expect(key.s2kUsage, S2kUsage.none);
          expect(key.symmetricAlgorithm, SymmetricAlgorithm.plaintext);
          expect(key.iv, isNull);
          expect(key.s2k, isNull);

          final encryptedKey = key.encrypt(passphrase);
          expect(encryptedKey.fingerprint, key.fingerprint);
          expect(encryptedKey.secretParams, key.secretParams);

          expect(encryptedKey.s2kUsage, S2kUsage.sha1);
          expect(encryptedKey.symmetricAlgorithm, SymmetricAlgorithm.aes256);
          expect(encryptedKey.iv, isNotNull);
          expect(encryptedKey.s2k, isNotNull);

          final secretKey = SecretKeyPacket.fromPacketData(encryptedKey.toPacketData());
          expect(secretKey.isDecrypted, false);

          final decryptedKey = secretKey.decrypt(passphrase);
          final decryptedParams = decryptedKey.secretParams as RSASecretParams;

          expect(decryptedKey.fingerprint, key.fingerprint);
          expect(decryptedParams.privateExponent, secretParams.privateExponent);
          expect(decryptedParams.primeP, secretParams.primeP);
          expect(decryptedParams.primeQ, secretParams.primeQ);
          expect(decryptedParams.pInv, secretParams.pInv);
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as RSAPublicParams;
          final secretParams = subkey.secretParams as RSASecretParams;

          expect(subkey.fingerprint, 'c503083b150f47a5d6fdb661c865808a31866def');
          expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP.modInverse(secretParams.primeQ));
          expect(publicParams.modulus, secretParams.modulus);

          expect(subkey.isDecrypted, true);
          expect(subkey.s2kUsage, S2kUsage.none);
          expect(subkey.symmetricAlgorithm, SymmetricAlgorithm.plaintext);
          expect(subkey.iv, isNull);
          expect(subkey.s2k, isNull);

          final encryptedKey = subkey.encrypt(passphrase);
          expect(encryptedKey.fingerprint, subkey.fingerprint);
          expect(encryptedKey.secretParams, subkey.secretParams);

          expect(encryptedKey.s2kUsage, S2kUsage.sha1);
          expect(encryptedKey.symmetricAlgorithm, SymmetricAlgorithm.aes256);
          expect(encryptedKey.iv, isNotNull);
          expect(encryptedKey.s2k, isNotNull);

          final secretKey = SecretKeyPacket.fromPacketData(encryptedKey.toPacketData());
          expect(secretKey.isDecrypted, false);

          final decryptedKey = secretKey.decrypt(passphrase);
          final decryptedParams = decryptedKey.secretParams as RSASecretParams;

          expect(decryptedKey.fingerprint, subkey.fingerprint);
          expect(decryptedParams.privateExponent, secretParams.privateExponent);
          expect(decryptedParams.primeP, secretParams.primeP);
          expect(decryptedParams.primeQ, secretParams.primeQ);
          expect(decryptedParams.pInv, secretParams.pInv);
        }
      }
    }));
  });
}
