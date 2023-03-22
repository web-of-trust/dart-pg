// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/math/int_ext.dart';
import '../enum/packet_tag.dart';
import 'contained_packet.dart';
import 'image_attribute.dart';
import 'subpacket_reader.dart';
import 'user_attribute_subpacket.dart';

/// Implementation of the User Attribute Packet (Tag 17)
///
/// The User Attribute packet is a variation of the User ID packet.
/// It is capable of storing more types of data than the User ID packet, which is limited to text.
/// Like the User ID packet, a User Attribute packet may be certified by the key
/// owner ("self-signed") or any other key owner who cares to certify it.
/// Except as noted, a User Attribute packet may be used anywhere that a User ID packet may be used.
class UserAttributePacket extends ContainedPacket {
  final List<UserAttributeSubpacket> attributes;

  UserAttributePacket(this.attributes) : super(PacketTag.userAttribute);

  ImageAttributeSubpacket? get userImage {
    final attrs = attributes.whereType<ImageAttributeSubpacket>();
    return attrs.isNotEmpty ? attrs.first : null;
  }

  factory UserAttributePacket.fromByteData(final Uint8List bytes) => UserAttributePacket(
        _readSubpackets(bytes),
      );

  @override
  Uint8List toByteData() =>
      Uint8List.fromList(attributes.map((attr) => attr.encode()).expand((byte) => byte).toList(growable: false));

  Uint8List writeForSign() {
    final bytes = toByteData();
    return Uint8List.fromList([
      0xd1,
      ...bytes.lengthInBytes.pack32(),
      ...bytes,
    ]);
  }

  static List<UserAttributeSubpacket> _readSubpackets(final Uint8List bytes) {
    final attributes = <UserAttributeSubpacket>[];
    var offset = 0;
    while (offset < bytes.length) {
      final reader = SubpacketReader.read(bytes, offset);
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
