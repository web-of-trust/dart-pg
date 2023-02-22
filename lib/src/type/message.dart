// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../armor/armor.dart';
import '../enums.dart';
import '../helpers.dart';
import '../packet/packet_list.dart';

/// Class that represents an OpenPGP message.
/// Can be an encrypted message, signed message, compressed message or literal message
/// See {@link https://tools.ietf.org/html/rfc4880#section-11.3}
class Message {
  /// The packets that form this message
  final PacketList packetList;

  Message(this.packetList);

  /// Returns ASCII armored text of message
  String armor() => Armor.encode(ArmorType.message, packetList.packetEncode());

  static Uint8List generateSessionKey(SymmetricAlgorithm symmetric) =>
      Helper.secureRandom().nextBytes((symmetric.keySize + 7) >> 3);
}
