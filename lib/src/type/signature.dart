// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enum/armor_type.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';

/// Class that represents an OpenPGP signature.
class Signature {
  final List<SignaturePacket> packets;

  Signature(PacketList packetList)
      : packets =
            packetList.whereType<SignaturePacket>().toList(growable: false);

  factory Signature.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.signature) {
      throw ArgumentError('Armored text not of signature type');
    }
    return Signature(PacketList.packetDecode(armor.data));
  }

  List<String> get signingKeyIDs =>
      packets.map((packet) => packet.issuerKeyID.id).toList(growable: false);

  /// Returns ASCII armored text of signature
  String armor() =>
      Armor.encode(ArmorType.signature, PacketList(packets).encode());
}
