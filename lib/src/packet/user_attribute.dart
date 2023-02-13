// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';
import 'image_attribute.dart';
import 'subpacket_reader.dart';
import 'user_attribute_subpacket.dart';

class UserAttributePacket extends ContainedPacket {
  final List<UserAttributeSubpacket> attributes;

  UserAttributePacket(
    this.attributes, {
    super.tag = PacketTag.userAttribute,
  });

  ImageAttributeSubpacket? get userImage {
    final attrs = attributes.whereType<ImageAttributeSubpacket>();
    return attrs.isNotEmpty ? attrs.first : null;
  }

  factory UserAttributePacket.fromPacketData(final Uint8List bytes) => UserAttributePacket(_readSubpackets(bytes));

  @override
  Uint8List toPacketData() {
    final bytes = <int>[];
    for (final attr in attributes) {
      bytes.addAll(attr.toSubpacket());
    }
    return Uint8List.fromList(bytes);
  }

  static List<UserAttributeSubpacket> _readSubpackets(final Uint8List bytes) {
    final attributes = <UserAttributeSubpacket>[];
    var offset = 0;
    while (offset < bytes.length) {
      final reader = SubpacketReader.fromSubpacket(bytes, offset);
      offset = reader.end;
      if (reader.data.isNotEmpty) {
        switch (reader.type) {
          case ImageAttributeSubpacket.jpeg:
            attributes.add(ImageAttributeSubpacket(
              reader.data,
              isLongLength: reader.isLongLength,
            ));
            break;
          default:
            attributes.add(UserAttributeSubpacket(
              reader.type,
              reader.data,
              isLongLength: reader.isLongLength,
            ));
        }
      }
    }
    return attributes;
  }
}
