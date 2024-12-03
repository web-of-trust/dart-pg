/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/enum/signature_type.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/key_packet.dart';
import 'package:dart_pg/src/type/packet_list.dart';
import 'package:dart_pg/src/type/signature_packet.dart';
import 'package:dart_pg/src/type/subkey.dart';
import 'package:dart_pg/src/type/subkey_packet.dart';
import 'package:dart_pg/src/type/user.dart';
import 'subkey.dart';
import 'user.dart';

/// Base abstract OpenPGP key class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class BaseKey implements KeyInterface {
  @override
  late final KeyPacketInterface keyPacket;

  @override
  late final List<SignaturePacketInterface> revocationSignatures;

  @override
  late final List<SignaturePacketInterface> directSignatures;

  @override
  late final List<UserInterface> users;

  @override
  late final List<SubkeyInterface> subkeys;

  BaseKey(final PacketListInterface packetList) {
    _readPacketList(packetList);
  }

  @override
  DateTime get creationTime => keyPacket.creationTime;

  @override
  DateTime? get expirationTime {
    final time = keyExpiration(directSignatures.toList());
    if (time == null) {
      for (final user in users) {
        if (user.isPrimary) {
          return keyExpiration(user.selfSignatures.toList());
        }
      }
    }
    return time;
  }

  @override
  Uint8List get fingerprint => keyPacket.fingerprint;

  @override
  KeyAlgorithm get keyAlgorithm => keyPacket.keyAlgorithm;

  @override
  Uint8List get keyID => keyPacket.keyID;

  @override
  int get keyStrength => keyPacket.keyStrength;

  @override
  int get version => keyPacket.keyVersion;

  @override
  PacketListInterface get packetList => PacketList([
        keyPacket,
        ...revocationSignatures,
        ...directSignatures,
        ...users.map((user) => user.packetList).expand((packet) => packet),
        ...subkeys.map((subkey) => subkey.packetList).expand((packet) => packet),
      ]);

  _readPacketList(final PacketListInterface packetList) {
    final revocationSignatures = <SignaturePacketInterface>[];
    final directSignatures = <SignaturePacketInterface>[];
    final users = <UserInterface>[];
    final subkeys = <SubkeyInterface>[];

    KeyPacketInterface? keyPacket;
    Subkey? subkey;
    User? user;
    Uint8List? primaryKeyID;
    for (final packet in packetList) {
      switch (packet.type) {
        case PacketType.publicKey:
        case PacketType.secretKey:
          if (keyPacket != null) {
            throw StateError('Key block contains multiple key packets');
          }
          if (packet is KeyPacketInterface) {
            keyPacket = packet;
            primaryKeyID = packet.keyID;
          }
          break;
        case PacketType.publicSubkey:
        case PacketType.secretSubkey:
          if (packet is SubkeyPacketInterface) {
            subkey = Subkey(
              this,
              packet,
            );
            subkeys.add(subkey);
          }
          user = null;
          break;
        case PacketType.userID:
        case PacketType.userAttribute:
          if (packet is UserIDPacket) {
            user = User(
              this,
              packet,
            );
            users.add(user);
          }
          break;
        case PacketType.signature:
          if (packet is SignaturePacket) {
            switch (packet.signatureType) {
              case SignatureType.certGeneric:
              case SignatureType.certPersona:
              case SignatureType.certCasual:
              case SignatureType.certPositive:
                if (packet.issuerKeyID == primaryKeyID) {
                  user?.selfSignatures.add(packet);
                } else {
                  user?.otherSignatures.add(packet);
                }
                break;
              case SignatureType.certRevocation:
                user?.revocationSignatures.add(packet);
                break;
              case SignatureType.subkeyBinding:
                subkey?.bindingSignatures.add(packet);
                break;
              case SignatureType.subkeyRevocation:
                subkey?.revocationSignatures.add(packet);
                break;
              case SignatureType.directKey:
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
      throw StateError('Key packet not found in packet list');
    }

    this.keyPacket = keyPacket;
    this.revocationSignatures = revocationSignatures;
    this.directSignatures = directSignatures;
    this.users = users.where((user) => user.verify()).toList();
    this.subkeys = subkeys.where((subkey) => subkey.verify()).toList();
  }

  static DateTime? keyExpiration(
    final List<SignaturePacketInterface> signatures,
  ) {
    signatures.sort(
      (a, b) => b.creationTime.compareTo(
        a.creationTime,
      ),
    );
    for (final signature in signatures) {
      if (signature.keyExpirationTime > 0) {
        final creationTime = signature.creationTime;
        return creationTime.add(Duration(
          seconds: signature.keyExpirationTime,
        ));
      } else if (signature.expirationTime != null) {
        return signature.expirationTime;
      }
    }
    return null;
  }
}
