import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/src/packet/image_attribute.dart';
import 'package:dart_pg/src/packet/user_attribute.dart';
import 'package:dart_pg/src/packet/user_attribute_subpacket.dart';
import 'package:dart_pg/src/packet/user_id.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

void main() {
  group('User packet', (() {
    test('user id test', (() {
      final name = faker.person.name();
      final email = faker.internet.email().replaceAll("'", '');
      final comment = faker.lorem.words(3).join(' ');

      final userID = UserIDPacket([name, '($comment)', '<$email>'].join(' '));
      expect(userID.name, name);
      expect(userID.email, email);
      expect(userID.comment, comment);

      final cloneUserId = UserIDPacket.fromByteData(userID.toByteData());
      expect(userID.name, cloneUserId.name);
      expect(userID.email, cloneUserId.email);
      expect(userID.comment, cloneUserId.comment);
    }));

    test('user attribute test', (() {
      final imageData =
          Uint8List.fromList(faker.randomGenerator.numbers(255, 100));
      final subpacketType = faker.randomGenerator.integer(100);
      final subpacketData =
          utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final userAttr = UserAttributePacket.fromByteData(UserAttributePacket([
        ImageAttributeSubpacket.fromImageData(imageData),
        UserAttributeSubpacket(subpacketType, subpacketData),
      ]).toByteData());
      final imageAttr = userAttr.attributes[0] as ImageAttributeSubpacket;
      final subpacket = userAttr.attributes[1];

      expect(imageAttr.version, 0x01);
      expect(imageAttr.encoding, ImageAttributeSubpacket.jpeg);
      expect(imageAttr.imageData, imageData);

      expect(subpacket.type, subpacketType);
      expect(subpacket.data, subpacketData);
    }));
  }));
}
