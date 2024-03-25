// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/signature_type.dart';
import '../packet/key/key_id.dart';
import '../packet/key/key_params.dart';
import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import '../packet/user_attribute.dart';
import '../packet/user_id.dart';
import 'public_key.dart';
import 'subkey.dart';
import 'user.dart';

export 'public_key.dart';
export 'private_key.dart';

/// Abstract class that represents an OpenPGP key. Must contain a primary key.
/// Can contain additional subkeys, signatures, user ids, user attributes.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class Key {
  final KeyPacket keyPacket;

  final Iterable<SignaturePacket> revocationSignatures;

  final Iterable<SignaturePacket> directSignatures;

  late final List<User> users;

  late final List<Subkey> subkeys;

  Key(
    this.keyPacket, {
    this.revocationSignatures = const [],
    this.directSignatures = const [],
    final Iterable<User> users = const [],
    final Iterable<Subkey> subkeys = const [],
  }) {
    this.users = users
        .map((user) => User(
              mainKey: this,
              userID: user.userID,
              userAttribute: user.userAttribute,
              selfCertifications: user.selfCertifications,
              otherCertifications: user.otherCertifications,
              revocationSignatures: user.revocationSignatures,
            ))
        .toList(growable: false);
    this.subkeys = subkeys
        .map((subkey) => Subkey(
              subkey.keyPacket,
              mainKey: this,
              bindingSignatures: subkey.bindingSignatures,
              revocationSignatures: subkey.revocationSignatures,
            ))
        .toList(growable: false);
  }

  DateTime get creationTime => keyPacket.creationTime;

  KeyAlgorithm get algorithm => keyPacket.algorithm;

  String get fingerprint => keyPacket.fingerprint;

  KeyID get keyID => keyPacket.keyID;

  KeyParams get publicParams => keyPacket.publicParams;

  int get keyStrength => keyPacket.keyStrength;

  bool get isPrivate => keyPacket.tag == PacketTag.secretKey;

  PublicKey get toPublic;

  bool get isEncryptionKey {
    if (keyPacket.isEncryptionKey) {
      for (final user in users) {
        for (var signature in user.selfCertifications) {
          if (signature.keyFlags != null &&
              !(signature.keyFlags!.isEncryptStorage || signature.keyFlags!.isEncryptCommunication)) {
            return false;
          }
        }
      }
    }
    return keyPacket.isEncryptionKey;
  }

  bool get isSigningKey {
    if (keyPacket.isSigningKey) {
      for (final user in users) {
        for (var signature in user.selfCertifications) {
          if (signature.keyFlags != null && !signature.keyFlags!.isSignData) {
            return false;
          }
        }
      }
    }
    return keyPacket.isSigningKey;
  }

  bool get aeadSupported {
    for (final user in users) {
      for (var signature in user.selfCertifications) {
        if (signature.features != null && signature.features!.supportAeadEncryptedData) {
          return true;
        }
      }
    }
    return false;
  }

  /// Returns ASCII armored text of key
  String armor();

  /// Verify primary key.
  /// Checks for revocation signatures, expiration time and valid self signature.
  Future<bool> verifyPrimaryKey({
    final String userID = '',
    final DateTime? date,
  }) async {
    if (await isRevoked(date: date)) {
      return false;
    }
    final user = await getPrimaryUser(userID: userID, date: date);
    if (!await user.verify(date: date)) {
      return false;
    }
    for (final signature in directSignatures) {
      if (!await signature.verify(
        keyPacket,
        keyPacket.writeForSign(),
        date: date,
      )) {
        return false;
      }
    }
    return true;
  }

  Future<User> getPrimaryUser({
    final String userID = '',
    final DateTime? date,
  }) async {
    final validUsers = <User>[];
    for (final user in users) {
      if (user.userID == null) {
        continue;
      }
      final selfCertifications = user.selfCertifications
        ..sort(
          (a, b) => b.creationTime.creationTime.compareTo(
            a.creationTime.creationTime,
          ),
        );
      if (await user.isRevoked(
        date: date,
        signature: selfCertifications.isNotEmpty ? selfCertifications[0] : null,
      )) {
        continue;
      }
      validUsers.add(user);
    }
    if (validUsers.isEmpty) {
      throw StateError('Could not find primary user');
    }
    for (final user in validUsers) {
      if (userID.isNotEmpty && user.userID!.userID != userID) {
        throw StateError('Could not find user that matches that user ID');
      }
    }
    return validUsers[0];
  }

  /// Checks if a signature on a key is revoked
  Future<bool> isRevoked({
    final SignaturePacket? signature,
    final DateTime? date,
  }) async {
    if (revocationSignatures.isNotEmpty) {
      final revocationKeyIDs = <String>[];
      for (final revocation in revocationSignatures) {
        if (signature == null || revocation.issuerKeyID.id == signature.issuerKeyID.id) {
          if (await revocation.verify(
            keyPacket,
            keyPacket.writeForSign(),
            date: date,
          )) {
            return true;
          }
        }
        revocationKeyIDs.add(revocation.issuerKeyID.id);
      }
      return revocationKeyIDs.isNotEmpty;
    }
    return false;
  }

  Future<DateTime?> getExpirationTime() async {
    DateTime? expirationTime;
    final signatures = directSignatures.toList(growable: false)
      ..sort(
        (a, b) => b.creationTime.creationTime.compareTo(
          a.creationTime.creationTime,
        ),
      );
    for (final signature in signatures) {
      if (signature.keyExpirationTime != null) {
        final keyExpirationTime = signature.keyExpirationTime!.time;
        final creationTime = signature.creationTime.creationTime;
        expirationTime = creationTime.add(Duration(seconds: keyExpirationTime));
        break;
      }
    }
    if (expirationTime == null) {
      final user = await getPrimaryUser();
      user.selfCertifications.sort(
        (a, b) => b.creationTime.creationTime.compareTo(
          a.creationTime.creationTime,
        ),
      );
      for (final signature in user.selfCertifications) {
        if (signature.keyExpirationTime != null) {
          final keyExpirationTime = signature.keyExpirationTime!.time;
          final creationTime = signature.creationTime.creationTime;
          expirationTime = creationTime.add(
            Duration(seconds: keyExpirationTime),
          );
          break;
        }
      }
    }
    return expirationTime;
  }

  PacketList toPacketList() => PacketList([
        keyPacket,
        ...revocationSignatures,
        ...directSignatures,
        ...users.map((user) => user.toPacketList()).expand((packet) => packet),
        ...subkeys.map((subkey) => subkey.toPacketList()).expand((packet) => packet),
      ]);

  static Map<String, dynamic> readPacketList(final PacketList packetList) {
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
                  if (packet.issuerKeyID.id == primaryKeyID) {
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
      throw StateError('Key packet not found in packet list');
    }

    return {
      'keyPacket': keyPacket,
      'users': users,
      'revocationSignatures': revocationSignatures,
      'directSignatures': directSignatures,
      'subkeys': subkeys,
    };
  }
}
