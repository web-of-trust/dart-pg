/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../common/helpers.dart';
import '../type/user_id_packet.dart';
import 'base_packet.dart';

/// User ID (UID) Packet - Type 13
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class UserIDPacket extends BasePacket implements UserIDPacketInterface {
  final String userID;

  final String name;

  final String email;

  final String comment;

  UserIDPacket(this.userID)
      : name = _extractName(userID),
        email = _extractEmail(userID),
        comment = _extractComment(userID),
        super(PacketType.userID);

  factory UserIDPacket.fromBytes(
    final Uint8List bytes,
  ) =>
      UserIDPacket(utf8.decode(bytes));

  @override
  get data => userID.toBytes();

  @override
  get signBytes => Uint8List.fromList([
        0xb4,
        ...data.length.pack32(),
        ...data,
      ]);

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
