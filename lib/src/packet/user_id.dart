// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

class UserIDPacket extends ContainedPacket {
  final String name;

  final String email;

  final String comment;

  UserIDPacket(
    this.name,
    this.email, {
    this.comment = '',
    super.tag = PacketTag.userID,
  });

  factory UserIDPacket.fromPacketData(final Uint8List bytes) {
    final userID = utf8.decode(bytes);
    return UserIDPacket(
      _extractName(userID),
      _extractEmail(userID),
      comment: _extractComment(userID),
    );
  }

  @override
  Uint8List toPacketData() {
    final List<String> userID = [];
    if (name.isNotEmpty) {
      userID.add(name);
    }
    if (comment.isNotEmpty) {
      userID.add("($comment)");
    }
    if (email.isNotEmpty) {
      userID.add(email);
    }
    return utf8.encoder.convert(userID.join(' '));
  }

  static String _extractName(final String userID) {
    final List<String> name = [];
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
