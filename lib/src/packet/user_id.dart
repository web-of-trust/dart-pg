// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';
import 'contained_packet.dart';

class UserIDPacket extends ContainedPacket {
  final String userID;

  final String name;

  final String email;

  final String comment;

  UserIDPacket(
    this.userID, {
    super.tag = PacketTag.userID,
  })  : name = _extractName(userID),
        email = _extractEmail(userID),
        comment = _extractComment(userID);

  factory UserIDPacket.fromPacketData(final Uint8List bytes) {
    return UserIDPacket(utf8.decode(bytes));
  }

  @override
  Uint8List toPacketData() {
    return userID.stringToBytes();
  }

  Uint8List writeForSign() {
    final bytes = toPacketData();
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
    final pattern = RegExp(r'\b[\w\.-]+@[\w\.-]+\.\w{2,4}\b', caseSensitive: false);
    final match = pattern.firstMatch(userID);
    return match?.group(0) ?? '';
  }

  static String _extractComment(final String userID) {
    if (userID.contains('(') && userID.contains(')')) {
      return userID.substring(userID.indexOf('(') + 1, userID.indexOf(')'));
    } else {
      return '';
    }
  }
}
