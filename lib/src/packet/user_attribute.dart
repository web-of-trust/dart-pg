// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';
import 'image_attribute.dart';
import 'subpacket_range.dart';
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
    final List<int> bytes = [];
    for (final attr in attributes) {
      bytes.addAll(attr.write());
    }
    return Uint8List.fromList(bytes);
  }

  static List<UserAttributeSubpacket> _readSubpackets(final Uint8List bytes) {
    final List<UserAttributeSubpacket> attributes = [];
    var offset = 0;
    while (offset < bytes.length) {
      final range = SubpacketRange.readSubpacketRange(bytes.sublist(offset));
      offset += range.offset;
      final data = bytes.sublist(offset, offset + range.length);
      offset += range.length;
      if (data.isNotEmpty) {
        final type = data[0];
        switch (type) {
          case ImageAttributeSubpacket.jpeg:
            attributes.add(ImageAttributeSubpacket(data.sublist(1), longLength: range.offset == 5));
            break;
          default:
            attributes.add(UserAttributeSubpacket(type, data.sublist(1), longLength: range.offset == 5));
        }
      }
    }
    return attributes;
  }
}
