// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/public_key.dart';
import '../packet/public_subkey.dart';
import '../packet/signature.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'key.dart';

/// Class that represents an OpenPGP Public Key
class PublicKey extends Key {
  PublicKey(
    PublicKeyPacket? keyPacket, {
    List<PublicSubkeyPacket> subKeyPackets = const [],
    super.userIDPackets,
    super.userAttributes,
    super.signaturePackets,
  }) : super(keyPacket, subKeyPackets: subKeyPackets);

  factory PublicKey.fromPacketList(PacketList packetList) {
    PublicKeyPacket? keyPacket;
    final List<PublicSubkeyPacket> subKeyPackets = [];
    final List<UserIDPacket> userIDPackets = [];
    final List<UserAttributePacket> userAttributes = [];
    final List<SignaturePacket> signaturePackets = [];

    for (var packet in packetList) {
      switch (packet.tag) {
        case PacketTag.publicKey:
          if (packet is PublicKeyPacket) {
            keyPacket = packet;
          }
          break;
        case PacketTag.publicSubkey:
          if (packet is PublicSubkeyPacket) {
            subKeyPackets.add(packet);
          }
          break;
        case PacketTag.userID:
          if (packet is UserIDPacket) {
            userIDPackets.add(packet);
          }
          break;
        case PacketTag.userAttribute:
          if (packet is UserAttributePacket) {
            userAttributes.add(packet);
          }
          break;
        case PacketTag.signature:
          if (packet is SignaturePacket) {
            signaturePackets.add(packet);
          }
          break;
        default:
      }
    }
    return PublicKey(
      keyPacket,
      subKeyPackets: subKeyPackets,
      userIDPackets: userIDPackets,
      userAttributes: userAttributes,
      signaturePackets: signaturePackets,
    );
  }

  @override
  bool get isPrivate => false;

  @override
  String get armor => Armor.encode(ArmorType.publicKey, toPacketList().packetEncode());

  @override
  PublicKey get toPublic => this;
}
