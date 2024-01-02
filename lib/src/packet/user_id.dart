// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/math/int_ext.dart';
import '../enum/packet_tag.dart';
import '../helpers.dart';
import 'contained_packet.dart';

/// Implementation of the User ID Packet (Tag 13)
///
/// A User ID packet consists of UTF-8 text that is intended to represent the name and email address of the key holder.
/// By convention, it includes an RFC2822 mail name-addr, but there are no restrictions on its content.
/// The packet length in the header specifies the length of the User ID.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class UserIDPacket extends ContainedPacket {
  final String userID;

  final String name;

  final String email;

  final String comment;

  UserIDPacket(this.userID)
      : name = _extractName(userID),
        email = _extractEmail(userID),
        comment = _extractComment(userID),
        super(PacketTag.userID);

  factory UserIDPacket.fromByteData(final Uint8List bytes) {
    return UserIDPacket(utf8.decode(bytes));
  }

  @override
  Uint8List toByteData() {
    return userID.stringToBytes();
  }

  Uint8List writeForSign() {
    final bytes = toByteData();
    return Uint8List.fromList([
      0xb4,
      ...bytes.lengthInBytes.pack32(),
      ...bytes,
    ]);
  }

  static String _extractName(final String userID) {
    final name = <String>[];
    final chars = userID.split('');
    for (final char in chars) {
      if (char == '(' || char == '<') {
        break;
      }
      name.add(char);
    }
    return name.join('').trim();
  }

  static String _extractEmail(final String userID) {
    final match = RegExp(
      r'\b[\w\.-]+@[\w\.-]+\.\w{2,4}\b',
      caseSensitive: false,
    ).firstMatch(userID);
    return match?.group(0) ?? '';
  }

  static String _extractComment(final String userID) {
    if (userID.contains('(') && userID.contains(')')) {
      return userID.substring(
        userID.indexOf('(') + 1,
        userID.indexOf(')'),
      );
    } else {
      return '';
    }
  }
}
