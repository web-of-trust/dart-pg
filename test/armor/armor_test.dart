import 'dart:convert';

import 'package:dart_pg/dart_pg.dart';
import 'package:dart_pg/src/armor/armor.dart';
import 'package:dart_pg/src/armor/crc24.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('armor tests', (() {
    final faker = Faker();

    test('crc24 test', (() {
      final bytes = utf8.encoder.convert('Lore ipsum dolor sit amet');
      final crc = Crc24.calculate(bytes);
      final base64Crc = Crc24.base64Calculate(bytes);

      expect(crc, 14200356);
      expect(base64Crc, '2K4k');
    }));

    test('armor multipart section test', (() {
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

      final deArmor = Armor.decode(armored);
      expect(deArmor['type'], ArmorType.multipartSection);
      expect(deArmor['data'], bytes);
    }));

    test('armor multipart last test', (() {
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

      final deArmor = Armor.decode(armored);
      expect(deArmor['type'], ArmorType.multipartLast);
      expect(deArmor['data'], bytes);
    }));

    test('armor signed message test', (() {
      final text = faker.lorem.words(100).join(' ');
      final bytes = utf8.encoder.convert(text);

      final armored = Armor.encode(
        ArmorType.signedMessage,
        bytes,
        text: text,
        hashAlgo: OpenPGP.preferredHashAlgorithm.digestName,
      );

      final beginReg = RegExp(r'BEGIN PGP SIGNED MESSAGE-');
      expect(beginReg.hasMatch(armored), true);

      final beginSignReg = RegExp(r'BEGIN PGP SIGNATURE');
      expect(beginSignReg.hasMatch(armored), true);

      final endSignReg = RegExp(r'END PGP SIGNATURE');
      expect(endSignReg.hasMatch(armored), true);

      final deArmor = Armor.decode(armored);
      expect(deArmor['type'], ArmorType.signedMessage);
      expect(deArmor['data'], bytes);
      expect(deArmor['text'], text);
    }));

    test('armor message test', (() {
      final message = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.message,
        message,
      );

      final beginReg = RegExp(r'BEGIN PGP MESSAGE');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP MESSAGE');
      expect(endReg.hasMatch(armored), true);

      final deArmor = Armor.decode(armored);
      expect(deArmor['type'], ArmorType.message);
      expect(deArmor['data'], message);
    }));

    test('armor public key test', (() {
      final publicKey = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.publicKey,
        publicKey,
      );

      final beginReg = RegExp(r'BEGIN PGP PUBLIC KEY BLOCK');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP PUBLIC KEY BLOCK');
      expect(endReg.hasMatch(armored), true);

      final deArmor = Armor.decode(armored);
      expect(deArmor['type'], ArmorType.publicKey);
      expect(deArmor['data'], publicKey);
    }));

    test('armor private key test', (() {
      final privateKey = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.privateKey,
        privateKey,
      );

      final beginReg = RegExp(r'BEGIN PGP PRIVATE KEY BLOCK');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP PRIVATE KEY BLOCK');
      expect(endReg.hasMatch(armored), true);

      final deArmor = Armor.decode(armored);
      expect(deArmor['type'], ArmorType.privateKey);
      expect(deArmor['data'], privateKey);
    }));

    test('armor signature test', (() {
      final signature = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final armored = Armor.encode(
        ArmorType.signature,
        signature,
      );

      final beginReg = RegExp(r'BEGIN PGP SIGNATURE');
      expect(beginReg.hasMatch(armored), true);

      final endReg = RegExp(r'END PGP SIGNATURE');
      expect(endReg.hasMatch(armored), true);

      final deArmor = Armor.decode(armored);
      expect(deArmor['type'], ArmorType.signature);
      expect(deArmor['data'], signature);
    }));
  }));
}
