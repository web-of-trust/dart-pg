import 'dart:typed_data';

import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/helpers.dart';

import 'package:dart_pg/src/packet/signature_subpacket.dart';
import 'package:dart_pg/src/packet/subpacket_reader.dart';
import 'package:test/test.dart';

void main() {
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
