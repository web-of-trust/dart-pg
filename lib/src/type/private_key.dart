// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/key_packet.dart';
import 'key.dart';
import 'key_reader.dart';
import 'public_key.dart';

/// Class that represents an OpenPGP Private Key
class PrivateKey extends Key {
  PrivateKey(
    SecretKeyPacket keyPacket, {
    super.users,
    super.revocationSignatures,
    super.directSignatures,
    super.subkeys,
  }) : super(keyPacket);

  factory PrivateKey.fromArmored(String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.privateKey) {
      throw ArgumentError('Armored text not of private key type');
    }
    return PrivateKey.fromPacketList(PacketList.packetDecode(armor.data));
  }

  factory PrivateKey.fromPacketList(PacketList packetList) {
    final keyReader = KeyReader.fromPacketList(packetList);
    if (keyReader.keyPacket is! SecretKeyPacket) {
      throw ArgumentError('Key packet not of secret key type');
    }
    return PrivateKey(
      keyReader.keyPacket as SecretKeyPacket,
      revocationSignatures: keyReader.revocationSignatures,
      directSignatures: keyReader.directSignatures,
      users: keyReader.users,
      subkeys: keyReader.subkeys,
    );
  }

  @override
  bool get isPrivate => true;

  @override
  PublicKey get toPublic {
    final packetList = PacketList([]);
    final packets = toPacketList();
    for (final packet in packets) {
      switch (packet.tag) {
        case PacketTag.secretKey:
          if (packet is SecretKeyPacket) {
            packetList.add(packet.publicKey);
          }
          break;
        case PacketTag.secretSubkey:
          if (packet is SecretSubkeyPacket) {
            packetList.add(packet.publicKey);
          }
          break;
        default:
          packetList.add(packet);
      }
    }
    return PublicKey.fromPacketList((packetList));
  }

  @override
  String armor() => Armor.encode(ArmorType.privateKey, toPacketList().packetEncode());
}
