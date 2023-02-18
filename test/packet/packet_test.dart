import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/helpers.dart';

import 'package:dart_pg/src/packet/key/dsa_public_params.dart';
import 'package:dart_pg/src/packet/key/dsa_secret_params.dart';
import 'package:dart_pg/src/packet/key/ec_secret_params.dart';
import 'package:dart_pg/src/packet/key/ecdh_public_params.dart';
import 'package:dart_pg/src/packet/key/ecdsa_public_params.dart';
import 'package:dart_pg/src/packet/key/elgamal_public_params.dart';
import 'package:dart_pg/src/packet/key/elgamal_secret_params.dart';
import 'package:dart_pg/src/packet/key/rsa_public_params.dart';
import 'package:dart_pg/src/packet/key/rsa_secret_params.dart';
import 'package:dart_pg/src/packet/image_attribute.dart';
import 'package:dart_pg/src/packet/public_key.dart';
import 'package:dart_pg/src/packet/public_subkey.dart';
import 'package:dart_pg/src/packet/secret_key.dart';
import 'package:dart_pg/src/packet/secret_subkey.dart';
import 'package:dart_pg/src/packet/signature_subpacket.dart';
import 'package:dart_pg/src/packet/subpacket_reader.dart';
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
      final publicKey = PublicKeyPacket.fromPacketData(
          base64.decode(rsaPublicKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      expect(publicKey.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
      expect(publicKey.algorithm, KeyAlgorithm.rsaEncryptSign);

      final publicSubkey = PublicSubkeyPacket.fromPacketData(
          base64.decode(rsaPublicSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      expect(publicSubkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
      expect(publicSubkey.algorithm, KeyAlgorithm.rsaEncryptSign);
    });

    test('dsa elgamal test', () {
      final publicKey = PublicKeyPacket.fromPacketData(
          base64.decode(dsaPublicKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      expect(publicKey.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
      expect(publicKey.algorithm, KeyAlgorithm.dsa);

      final publicSubkey = PublicSubkeyPacket.fromPacketData(
          base64.decode(elgamalPublicSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      expect(publicSubkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
      expect(publicSubkey.algorithm, KeyAlgorithm.elgamal);
    });

    test('ecc test', () {
      final publicKey = PublicKeyPacket.fromPacketData(
          base64.decode(ecdsaPublicKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      expect(publicKey.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
      expect(publicKey.algorithm, KeyAlgorithm.ecdsa);

      final publicSubkey = PublicSubkeyPacket.fromPacketData(
          base64.decode(ecdhPublicSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      expect(publicSubkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
      expect(publicSubkey.algorithm, KeyAlgorithm.ecdh);
    });
  });

  group('secret key packet tests', () {
    test('rsa test', (() {
      final secretKey = SecretKeyPacket.fromPacketData(
          base64.decode(rsaSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final publicParams = secretKey.publicKey.publicParams as RSAPublicParams;
      final secretParams = secretKey.decrypt(passphrase).secretParams as RSASecretParams;

      expect(secretKey.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
      expect(secretKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(secretParams.pInv, secretParams.primeP.modInverse(secretParams.primeQ));
      expect(publicParams.modulus, secretParams.modulus);

      final secretSubkey = SecretSubkeyPacket.fromPacketData(
          base64.decode(rsaSecretSubkeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final subkeyPublicParams = secretSubkey.publicKey.publicParams as RSAPublicParams;
      final subkeySecretParams = secretSubkey.decrypt(passphrase).secretParams as RSASecretParams;

      expect(secretSubkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
      expect(secretSubkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkeySecretParams.pInv, subkeySecretParams.primeP.modInverse(subkeySecretParams.primeQ));
      expect(subkeyPublicParams.modulus, subkeySecretParams.modulus);
    }));

    test('dsa elgamal test', () {
      final secretKey = SecretKeyPacket.fromPacketData(
          base64.decode(dsaSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final publicParams = secretKey.publicKey.publicParams as DSAPublicParams;
      final secretParams = secretKey.decrypt(passphrase).secretParams as DSASecretParams;

      expect(secretKey.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
      expect(secretKey.algorithm, KeyAlgorithm.dsa);
      expect(publicParams.publicExponent,
          publicParams.groupGenerator.modPow(secretParams.secretExponent, publicParams.primeP));

      final secretSubkey = SecretSubkeyPacket.fromPacketData(
          base64.decode(elgamalSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final subkeyPublicParams = secretSubkey.publicKey.publicParams as ElGamalPublicParams;
      final subkeySecretParams = secretSubkey.decrypt(passphrase).secretParams as ElGamalSecretParams;

      expect(secretSubkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
      expect(secretSubkey.algorithm, KeyAlgorithm.elgamal);
      expect(subkeyPublicParams.publicExponent,
          subkeyPublicParams.groupGenerator.modPow(subkeySecretParams.secretExponent, subkeyPublicParams.primeP));
    });

    test('ecc test', () {
      final secretKey = SecretKeyPacket.fromPacketData(
          base64.decode(ecdsaSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final publicParams = secretKey.publicKey.publicParams as ECDSAPublicParams;
      final secretParams = secretKey.decrypt(passphrase).secretParams as ECSecretParams;

      expect(secretKey.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
      expect(secretKey.algorithm, KeyAlgorithm.ecdsa);
      expect(publicParams.publicKey.Q, publicParams.publicKey.parameters!.G * secretParams.d);

      final secretSubkey = SecretSubkeyPacket.fromPacketData(
          base64.decode(ecdhSecretKeyPacket.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final subkeyPublicParams = secretSubkey.publicKey.publicParams as ECDHPublicParams;
      final subkeySecretParams = secretSubkey.decrypt(passphrase).secretParams as ECSecretParams;

      expect(secretSubkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
      expect(secretSubkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkeyPublicParams.publicKey.Q, subkeyPublicParams.publicKey.parameters!.G * subkeySecretParams.d);
    });

    test('encrypt test', (() {
      final secretKey = SecretKeyPacket.fromPacketData(
          base64.decode(secretKeyPacketWithoutPassphase.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final publicParams = secretKey.publicKey.publicParams as RSAPublicParams;
      final secretParams = secretKey.secretParams as RSASecretParams;

      expect(secretKey.fingerprint, '93456c517e3eddb679bb510c2213de9391374950');
      expect(secretKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(secretParams.pInv, secretParams.primeP.modInverse(secretParams.primeQ));
      expect(publicParams.modulus, secretParams.modulus);

      expect(secretKey.isDecrypted, true);
      expect(secretKey.s2kUsage, S2kUsage.none);
      expect(secretKey.symmetricAlgorithm, SymmetricAlgorithm.plaintext);
      expect(secretKey.iv, isNull);
      expect(secretKey.s2k, isNull);

      final encryptedKey = secretKey.encrypt(passphrase);
      expect(encryptedKey.fingerprint, secretKey.fingerprint);
      expect(encryptedKey.secretParams, secretKey.secretParams);

      expect(encryptedKey.s2kUsage, S2kUsage.sha1);
      expect(encryptedKey.symmetricAlgorithm, SymmetricAlgorithm.aes256);
      expect(encryptedKey.iv, isNotNull);
      expect(encryptedKey.s2k, isNotNull);

      final decryptedKey = SecretKeyPacket.fromPacketData(encryptedKey.toPacketData()).decrypt(passphrase);
      final decryptedParams = decryptedKey.secretParams as RSASecretParams;

      expect(decryptedKey.fingerprint, secretKey.fingerprint);
      expect(decryptedParams.privateExponent, secretParams.privateExponent);
      expect(decryptedParams.primeP, secretParams.primeP);
      expect(decryptedParams.primeQ, secretParams.primeQ);
      expect(decryptedParams.pInv, secretParams.pInv);

      final secretSubkey = SecretSubkeyPacket.fromPacketData(
          base64.decode(secretSubkeyPacketWithoutPassphase.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final subkeyPublicParams = secretSubkey.publicKey.publicParams as RSAPublicParams;
      final subkeySecretParams = secretSubkey.secretParams as RSASecretParams;

      expect(secretSubkey.fingerprint, 'c503083b150f47a5d6fdb661c865808a31866def');
      expect(secretSubkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkeySecretParams.pInv, subkeySecretParams.primeP.modInverse(subkeySecretParams.primeQ));
      expect(subkeyPublicParams.modulus, subkeySecretParams.modulus);

      expect(secretSubkey.isDecrypted, true);
      expect(secretSubkey.s2kUsage, S2kUsage.none);
      expect(secretSubkey.symmetricAlgorithm, SymmetricAlgorithm.plaintext);
      expect(secretSubkey.iv, isNull);
      expect(secretSubkey.s2k, isNull);

      final subkeyEncryptedKey = secretSubkey.encrypt(passphrase);
      expect(subkeyEncryptedKey.fingerprint, secretSubkey.fingerprint);
      expect(subkeyEncryptedKey.secretParams, secretSubkey.secretParams);

      expect(subkeyEncryptedKey.s2kUsage, S2kUsage.sha1);
      expect(subkeyEncryptedKey.symmetricAlgorithm, SymmetricAlgorithm.aes256);
      expect(subkeyEncryptedKey.iv, isNotNull);
      expect(subkeyEncryptedKey.s2k, isNotNull);

      final subkeyDecryptedKey = SecretKeyPacket.fromPacketData(subkeyEncryptedKey.toPacketData()).decrypt(passphrase);
      final subkeyDecryptedParams = subkeyDecryptedKey.secretParams as RSASecretParams;

      expect(subkeyDecryptedKey.fingerprint, secretSubkey.fingerprint);
      expect(subkeyDecryptedParams.privateExponent, subkeySecretParams.privateExponent);
      expect(subkeyDecryptedParams.primeP, subkeySecretParams.primeP);
      expect(subkeyDecryptedParams.primeQ, subkeySecretParams.primeQ);
      expect(subkeyDecryptedParams.pInv, subkeySecretParams.pInv);
    }));
  });

  group('signature packet tests', () {
    test('key flag sub packet', () {
      final keyFlags = KeyFlags.fromFlags(
        KeyFlag.certifyKeys.value |
            KeyFlag.signData.value |
            KeyFlag.encryptCommunication.value |
            KeyFlag.encryptStorage.value |
            KeyFlag.splitPrivateKey.value |
            KeyFlag.authentication.value |
            KeyFlag.sharedPrivateKey.value,
      );
      for (final flag in KeyFlag.values) {
        expect(keyFlags.flags & flag.value, flag.value);
      }
    });

    test('features sub packet', () {
      final features = Features.fromFeatures(SupportFeature.modificationDetection.value |
          SupportFeature.aeadEncryptedData.value |
          SupportFeature.version5PublicKey.value);
      expect(features.supprtModificationDetection, true);
      expect(features.supportAeadEncryptedData, true);
      expect(features.supportVersion5PublicKey, true);
    });

    test('signature sub packet write & read', () {
      final random = Helper.secureRandom();
      final initSubpackets =
          SignatureSubpacketType.values.map((type) => SignatureSubpacket(type, random.nextBytes(10))).toList();

      final bytes = Uint8List.fromList(
        initSubpackets.map((subpacket) => subpacket.toSubpacket()).expand((byte) => byte).toList(),
      );
      final subpackets = <SignatureSubpacket>[];
      var offset = 0;
      while (offset < bytes.length) {
        final reader = SubpacketReader.fromSubpacket(bytes, offset);
        offset = reader.end;
        final data = reader.data;
        if (data.isNotEmpty) {
          final critical = ((reader.type & 0x80) != 0);
          final type = SignatureSubpacketType.values.firstWhere((type) => type.value == (reader.type & 0x7f));
          subpackets.add(SignatureSubpacket(
            type,
            data,
            critical: critical,
            isLongLength: reader.isLongLength,
          ));
        }
      }

      expect(initSubpackets.length, subpackets.length);
      for (final subpacket in initSubpackets) {
        final index = initSubpackets.indexOf(subpacket);
        expect(subpacket.type, subpackets[index].type);
        expect(subpacket.data, equals(subpackets[index].data));
      }
    });
  });
}
