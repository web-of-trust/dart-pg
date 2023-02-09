// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/signature.dart';

/// Class that represents an OpenPGP signature.
class Signature {
  final PacketList packetList;

  Signature(this.packetList);

  factory Signature.fromArmored(String armored) {
    final unarmor = Armor.decode(armored);
    if (unarmor['type'] != ArmorType.signature) {
      throw Exception('Armored text not of signature type');
    }
    final packetList = PacketList.packetDecode(unarmor['data']);
    return Signature(PacketList(packetList.whereType<SignaturePacket>().toList()));
  }

  List<String> get signingKeyIDs => packetList.map((packet) => (packet as SignaturePacket).issuerKeyID.keyID).toList();

  String armor() => Armor.encode(ArmorType.signature, packetList.packetEncode());
}
