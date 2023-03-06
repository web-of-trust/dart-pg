// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enum/packet_tag.dart';
import '../enum/signature_type.dart';
import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import '../packet/subkey_packet.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'subkey.dart';
import 'user.dart';

class KeyReader {
  final KeyPacket keyPacket;

  final List<SignaturePacket> revocationSignatures;

  final List<SignaturePacket> directSignatures;

  final List<User> users;

  final List<Subkey> subkeys;

  KeyReader(
    this.keyPacket, {
    this.revocationSignatures = const [],
    this.directSignatures = const [],
    this.users = const [],
    this.subkeys = const [],
  });

  factory KeyReader.fromPacketList(final PacketList packetList) {
    final revocationSignatures = <SignaturePacket>[];
    final directSignatures = <SignaturePacket>[];
    final users = <User>[];
    final subkeys = <Subkey>[];

    KeyPacket? keyPacket;
    Subkey? subkey;
    User? user;
    String? primaryKeyID;
    for (final packet in packetList) {
      switch (packet.tag) {
        case PacketTag.publicKey:
        case PacketTag.secretKey:
          if (keyPacket != null) {
            throw StateError('Key block contains multiple keys');
          }
          if (packet is KeyPacket) {
            keyPacket = packet;
            primaryKeyID = packet.keyID.toString();
          }
          break;
        case PacketTag.publicSubkey:
        case PacketTag.secretSubkey:
          if (packet is SubkeyPacket) {
            subkey = Subkey(
              packet,
              revocationSignatures: [],
              bindingSignatures: [],
            );
            subkeys.add(subkey);
          }
          user = null;
          break;
        case PacketTag.userID:
          if (packet is UserIDPacket) {
            user = User(
              userID: packet,
              selfCertifications: [],
              otherCertifications: [],
              revocationSignatures: [],
            );
            users.add(user);
          }
          break;
        case PacketTag.userAttribute:
          if (packet is UserAttributePacket) {
            user = User(
              userAttribute: packet,
              selfCertifications: [],
              otherCertifications: [],
              revocationSignatures: [],
            );
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
      throw Exception('Key packet not found in packet list');
    }

    return KeyReader(
      keyPacket,
      users: users,
      revocationSignatures: revocationSignatures,
      directSignatures: directSignatures,
      subkeys: subkeys,
    );
  }
}
