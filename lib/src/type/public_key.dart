// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/key_packet.dart';
import 'key.dart';
import 'key_reader.dart';

/// Class that represents an OpenPGP Public Key
class PublicKey extends Key {
  PublicKey(
    PublicKeyPacket keyPacket, {
    super.revocationSignatures,
    super.directSignatures,
    super.users,
    super.subkeys,
  }) : super(keyPacket);

  factory PublicKey.fromArmored(String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.publicKey) {
      throw ArgumentError('Armored text not of public key type');
    }
    return PublicKey.fromPacketList(PacketList.packetDecode(armor.data));
  }

  factory PublicKey.fromPacketList(PacketList packetList) {
    final keyReader = KeyReader.fromPacketList(packetList);
    if (keyReader.keyPacket is! PublicKeyPacket) {
      throw ArgumentError('Key packet not of public key type');
    }
    return PublicKey(
      keyReader.keyPacket as PublicKeyPacket,
      revocationSignatures: keyReader.revocationSignatures,
      directSignatures: keyReader.directSignatures,
      users: keyReader.users,
      subkeys: keyReader.subkeys,
    );
  }

  @override
  PublicKeyPacket get keyPacket => super.keyPacket as PublicKeyPacket;

  @override
  PublicKey get toPublic => this;

  @override
  String armor() => Armor.encode(ArmorType.publicKey, toPacketList().packetEncode());
}
