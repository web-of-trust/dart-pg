import 'dart:convert';

import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/enum/hash_algorithm.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('armor tests', () {
    final faker = Faker();

    test('multipart section test', (() {
      final bytes = utf8.encoder.convert(faker.lorem.words(100).join(' '));
      final partIndex = faker.randomGenerator.integer(100);
      final partTotal = faker.randomGenerator.integer(100);

      final armored = Armor.encode(
        ArmorType.multipartSection,
        bytes,
        partIndex: partIndex,
        partTotal: partTotal,
      );
      final beginReg = RegExp(r'BEGIN PGP MESSAGE, PART \d+\/\d+');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP MESSAGE, PART \d+\/\d+');
      expect(endReg.hasMatch(armored), true);

      final armor = Armor.decode(armored);
      expect(armor.type, ArmorType.multipartSection);
      expect(armor.data, bytes);
    }));

    test('multipart last test', (() {
      final bytes = utf8.encoder.convert(faker.lorem.words(100).join(' '));
      final partIndex = faker.randomGenerator.integer(100);

      final armored = Armor.encode(
        ArmorType.multipartLast,
        bytes,
        partIndex: partIndex,
      );

      final beginReg = RegExp(r'BEGIN PGP MESSAGE, PART \d+');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP MESSAGE, PART \d+');
      expect(endReg.hasMatch(armored), true);

      final armor = Armor.decode(armored);
      expect(armor.type, ArmorType.multipartLast);
      expect(armor.data, bytes);
    }));

    test('signed message test', (() {
      final text = faker.lorem.words(100).join(' ');
      final bytes = utf8.encoder.convert(text);

      final armored = Armor.encode(
        ArmorType.signedMessage,
        bytes,
        text: text,
        hashAlgos: [
          HashAlgorithm.sha256.digestName.toUpperCase(),
        ],
      );

      final beginReg = RegExp(r'BEGIN PGP SIGNED MESSAGE');
      expect(beginReg.hasMatch(armored), true);

      final beginSignReg = RegExp(r'BEGIN PGP SIGNATURE');
      expect(beginSignReg.hasMatch(armored), true);

      final endSignReg = RegExp(r'END PGP SIGNATURE');
      expect(endSignReg.hasMatch(armored), true);

      final armor = Armor.decode(armored);
      expect(armor.type, ArmorType.signedMessage);
      expect(armor.data, bytes);
      expect(armor.text, text);
    }));

    test('message test', (() {
      final message = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.message,
        message,
      );

      final beginReg = RegExp(r'BEGIN PGP MESSAGE');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP MESSAGE');
      expect(endReg.hasMatch(armored), true);

      final armor = Armor.decode(armored);
      expect(armor.type, ArmorType.message);
      expect(armor.data, message);
    }));

    test('public key test', (() {
      final publicKey = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.publicKey,
        publicKey,
      );

      final beginReg = RegExp(r'BEGIN PGP PUBLIC KEY BLOCK');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP PUBLIC KEY BLOCK');
      expect(endReg.hasMatch(armored), true);

      final armor = Armor.decode(armored);
      expect(armor.type, ArmorType.publicKey);
      expect(armor.data, publicKey);
    }));

    test('private key test', (() {
      final privateKey = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.privateKey,
        privateKey,
      );

      final beginReg = RegExp(r'BEGIN PGP PRIVATE KEY BLOCK');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP PRIVATE KEY BLOCK');
      expect(endReg.hasMatch(armored), true);

      final armor = Armor.decode(armored);
      expect(armor.type, ArmorType.privateKey);
      expect(armor.data, privateKey);
    }));

    test('signature test', (() {
      final signature = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.signature,
        signature,
      );

      final beginReg = RegExp(r'BEGIN PGP SIGNATURE');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP SIGNATURE');
      expect(endReg.hasMatch(armored), true);

      final armor = Armor.decode(armored);
      expect(armor.type, ArmorType.signature);
      expect(armor.data, signature);
    }));
  });
}
