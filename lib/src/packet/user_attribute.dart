/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../type/user_id_packet.dart';
import '../common/extensions.dart';
import 'base.dart';
import 'image_user_attribute.dart';
import 'subpacket_reader.dart';
import 'user_attribute_subpacket.dart';

/// Implementation of the User Attribute Packet (Type 17)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class UserAttributePacket extends BasePacket implements UserIDPacketInterface {
  final List<UserAttributeSubpacket> attributes;

  UserAttributePacket(this.attributes) : super(PacketType.userAttribute);

  factory UserAttributePacket.fromBytes(
    final Uint8List bytes,
  ) =>
      UserAttributePacket(
        _readSubpackets(bytes),
      );

  @override
  Uint8List get data => Uint8List.fromList(
        attributes
            .map(
              (attr) => attr.encode(),
            )
            .expand((byte) => byte)
            .toList(growable: false),
      );

  @override
  Uint8List get signBytes => Uint8List.fromList([
        0xd1,
        ...data.length.pack32(),
        ...data,
      ]);

  static List<UserAttributeSubpacket> _readSubpackets(final Uint8List bytes) {
    final attributes = <UserAttributeSubpacket>[];
    var offset = 0;
    while (offset < bytes.length) {
      final reader = SubpacketReader.read(bytes, offset);
      offset = reader.offset;
      if (reader.data.isNotEmpty) {
        switch (reader.type) {
          case ImageUserAttribute.jpeg:
            attributes.add(ImageUserAttribute(
              reader.data,
              isLong: reader.isLong,
            ));
            break;
          default:
            attributes.add(UserAttributeSubpacket(
              reader.type,
              reader.data,
              isLong: reader.isLong,
            ));
        }
      }
    }
    return attributes;
  }
}
