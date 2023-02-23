// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import 'key.dart';

/// Class that represents an OpenPGP message.
/// Can be an encrypted message, signed message, compressed message or literal message
/// See {@link https://tools.ietf.org/html/rfc4880#section-11.3}
class Message {
  /// The packets that form this message
  final PacketList packetList;

  Message(this.packetList);

  /// Returns ASCII armored text of message
  String armor() => Armor.encode(ArmorType.message, packetList.packetEncode());

  static encryptSessionKey(
    final Uint8List sessionKey,
    final SymmetricAlgorithm symmetric,
    final List<PublicKey> encryptionKeys, {
    final String? passwords,
    final DateTime? date,
  }) {}
}
