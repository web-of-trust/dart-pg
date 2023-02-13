// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/public_key.dart';
import '../packet/public_subkey.dart';
import '../packet/signature_packet.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'key.dart';
import 'subkey.dart';
import 'user.dart';

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
    final unarmor = Armor.decode(armored);
    if (unarmor['type'] != ArmorType.publicKey) {
      throw Exception('Armored text not of public key type');
    }
    return PublicKey.fromPacketList(PacketList.packetDecode(unarmor['data']));
  }

  factory PublicKey.fromPacketList(PacketList packetList) {
    final List<SignaturePacket> revocationSignatures = [];
    final List<SignaturePacket> directSignatures = [];
    final List<User> users = [];
    final List<Subkey> subkeys = [];

    PublicKeyPacket? keyPacket;
    Subkey? subkey;
    User? user;
    String? primaryKeyID;
    for (final packet in packetList) {
      switch (packet.tag) {
        case PacketTag.publicKey:
          if (packet is PublicKeyPacket) {
            keyPacket = packet;
            primaryKeyID = packet.keyID.toString();
          }
          break;
        case PacketTag.publicSubkey:
          if (packet is PublicSubkeyPacket) {
            subkey = Subkey(packet);
            subkeys.add(subkey);
          }
          user = null;
          break;
        case PacketTag.userID:
          if (packet is UserIDPacket) {
            user = User(userID: packet);
            users.add(user);
          }
          break;
        case PacketTag.userAttribute:
          if (packet is UserAttributePacket) {
            user = User(userAttribute: packet);
            users.add(user);
          }
          break;
        case PacketTag.signature:
          if (packet is SignaturePacket) {
            switch (packet.signatureType) {
              case SignatureType.certGeneric:
              case SignatureType.certPersona:
              case SignatureType.certCasual:
              case SignatureType.certPositive:
                if (user != null) {
                  if (packet.issuerKeyID.keyID == primaryKeyID) {
                    user.selfCertifications.add(packet);
                  } else {
                    user.otherCertifications.add(packet);
                  }
                }
                break;
              case SignatureType.certRevocation:
                if (user != null) {
                  user.revocationSignatures.add(packet);
                } else {
                  directSignatures.add(packet);
                }
                break;
              case SignatureType.key:
                directSignatures.add(packet);
                break;
              case SignatureType.keyRevocation:
                revocationSignatures.add(packet);
                break;
              case SignatureType.subkeyBinding:
                if (subkey != null) {
                  subkey.bindingSignatures.add(packet);
                }
                break;
              case SignatureType.subkeyRevocation:
                if (subkey != null) {
                  subkey.revocationSignatures.add(packet);
                }
                break;
              default:
            }
          }
          break;
        default:
      }
    }

    if (keyPacket == null) {
      throw Exception('Public key packet not found in packet list');
    }

    return PublicKey(
      keyPacket,
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      users: users,
      subkeys: subkeys,
    );
  }

  @override
  bool get isPrivate => false;

  @override
  PublicKey get toPublic => this;

  @override
  String armor() => Armor.encode(ArmorType.publicKey, toPacketList().packetEncode());
}
