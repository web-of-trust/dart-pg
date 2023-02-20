import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:dart_pg/src/packet/key_packet.dart';
import 'package:dart_pg/src/packet/signature_packet.dart';

import 'package:dart_pg/src/packet/signature_subpacket.dart';
import 'package:dart_pg/src/packet/subpacket_reader.dart';
import 'package:dart_pg/src/packet/user_id.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../test_data.dart';

void main() {
  group('signature packet tests', () {
    final faker = Faker();
    final random = Helper.secureRandom();

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

    test('sign & verify', () {
      final name = faker.person.name();
      final email = faker.internet.email();
      final comment = faker.lorem.words(3).join(' ');

      final secretKey = SecretKeyPacket.fromPacketData(
          base64.decode(secretKeyPacketWithoutPassphase.replaceAll(RegExp(r'\r?\n', multiLine: true), '')));
      final dataToSign = random.nextBytes(100);
      final signature = SignaturePacket.createSignature(secretKey, SignatureType.standalone, dataToSign);

      expect(signature.verify(secretKey.publicKey, dataToSign), isTrue);

      final userID = UserIDPacket([name, '($comment)', email].join(' '));
      final selfCertificate = SignaturePacket.createSelfCertificate(secretKey, userID: userID);
      expect(selfCertificate.verifyUserCertification(secretKey.publicKey, userID: userID), isTrue);
    });
  });
}
