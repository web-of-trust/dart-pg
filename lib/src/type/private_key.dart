// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enums.dart';
import '../packet/packet_list.dart';
import '../packet/secret_key.dart';
import '../packet/secret_subkey.dart';
import '../packet/signature.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'key.dart';
import 'public_key.dart';
import 'subkey.dart';
import 'user.dart';

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
    final unarmor = Armor.decode(armored);
    if (unarmor['type'] != ArmorType.privateKey) {
      throw Exception('Armored text not of private key type');
    }
    return PrivateKey.fromPacketList(PacketList.packetDecode(unarmor['data']));
  }

  factory PrivateKey.fromPacketList(PacketList packetList) {
    final revocationSignatures = <SignaturePacket>[];
    final directSignatures = <SignaturePacket>[];
    final users = <User>[];
    final subkeys = <Subkey>[];

    SecretKeyPacket? keyPacket;
    Subkey? subkey;
    User? user;
    String? primaryKeyID;
    for (final packet in packetList) {
      switch (packet.tag) {
        case PacketTag.secretKey:
          if (packet is SecretKeyPacket) {
            keyPacket = packet;
            primaryKeyID = packet.keyID.toString();
          }
          break;
        case PacketTag.secretSubkey:
          if (packet is SecretSubkeyPacket) {
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
              case SignatureType.key:
                directSignatures.add(packet);
                break;
              case SignatureType.keyRevocation:
                revocationSignatures.add(packet);
                break;
              default:
            }
          }
          break;
        default:
      }
    }

    if (keyPacket == null) {
      throw Exception('Secret key packet not found in packet list');
    }

    return PrivateKey(
      keyPacket,
      users: users,
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      subkeys: subkeys,
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
