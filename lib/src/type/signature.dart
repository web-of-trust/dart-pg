// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';

/// Class that represents an OpenPGP signature.
class Signature {
  final PacketList packetList;

  Signature(PacketList packetList) : packetList = PacketList(packetList.whereType<SignaturePacket>());

  factory Signature.fromArmored(String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.signature) {
      throw Exception('Armored text not of signature type');
    }
    return Signature(PacketList.packetDecode(armor.data));
  }

  List<String> get signingKeyIDs => packetList.map((packet) => (packet as SignaturePacket).issuerKeyID.keyID).toList();

  /// Returns ASCII armored text of signature
  String armor() => Armor.encode(ArmorType.signature, packetList.packetEncode());
}
