// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../enums.dart';
import '../packet/key/key_id.dart';
import '../packet/key/key_params.dart';
import '../packet/key_packet.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import 'public_key.dart';
import 'subkey.dart';
import 'user.dart';

export 'public_key.dart';
export 'private_key.dart';

/// Abstract class that represents an OpenPGP key. Must contain a primary key.
/// Can contain additional subkeys, signatures, user ids, user attributes.
abstract class Key {
  final KeyPacket keyPacket;

  final List<SignaturePacket> revocationSignatures;

  final List<SignaturePacket> directSignatures;

  final List<User> users;

  final List<Subkey> subkeys;

  Key(
    this.keyPacket, {
    this.revocationSignatures = const [],
    this.directSignatures = const [],
    this.users = const [],
    this.subkeys = const [],
  });

  DateTime get creationTime => keyPacket.creationTime;

  KeyAlgorithm get algorithm => keyPacket.algorithm;

  String get fingerprint => keyPacket.fingerprint;

  KeyID get keyID => keyPacket.keyID;

  KeyParams get publicParams => keyPacket.publicParams;

  int get keyStrength => keyPacket.keyStrength;

  bool get isPrivate => keyPacket.tag == PacketTag.secretKey;

  PublicKey get toPublic;

  bool get isSigningKey {
    if (keyPacket.isSigningKey) {
      for (final user in users) {
        for (var signature in user.selfCertifications) {
          if (signature.keyFlags == null) {
            continue;
          } else if ((signature.keyFlags!.flags & KeyFlag.signData.value) == 0) {
            return false;
          }
        }
      }
    }
    return keyPacket.isSigningKey;
  }

  bool get isEncryptionKey {
    if (keyPacket.isEncryptionKey) {
      for (final user in users) {
        for (var signature in user.selfCertifications) {
          if (signature.keyFlags == null) {
            continue;
          } else if ((signature.keyFlags!.flags & KeyFlag.signData.value) == KeyFlag.signData.value) {
            return false;
          }
        }
      }
    }
    return keyPacket.isEncryptionKey;
  }

  /// Returns ASCII armored text of key
  String armor();

  /// Verify primary key.
  /// Checks for revocation signatures, expiration time and valid self signature.
  bool verifyPrimaryKey({
    final String userID = '',
    final DateTime? date,
  }) {
    if (isRevoked(date: date)) {
      return false;
    }
    final user = getPrimaryUser(userID: userID, date: date);
    if (!user.verify(keyPacket, date: date)) {
      return false;
    }
    for (final signature in directSignatures) {
      if (!signature.verify(
        keyPacket,
        keyPacket.writeForSign(),
        date: date,
      )) {
        return false;
      }
    }
    return true;
  }

  User getPrimaryUser({
    final String userID = '',
    final DateTime? date,
  }) {
    final validUsers = <User>[];
    for (final user in users) {
      if (user.userID == null) {
        continue;
      }
      if (userID.isNotEmpty && user.userID!.userID != userID) {
        throw StateError('Could not find user that matches that user ID');
      }
      final selfCertifications = user.selfCertifications
        ..sort((a, b) => a.creationTime.creationTime.compareTo(b.creationTime.creationTime));
      if (user.isRevoked(
        keyPacket,
        date: date,
        signature: selfCertifications.isNotEmpty ? selfCertifications[0] : null,
      )) {
        continue;
      }
      validUsers.add(user);
      return user;
    }
    if (validUsers.isEmpty) {
      throw StateError('Could not find primary user');
    }
    return validUsers[0];
  }

  /// Checks if a signature on a key is revoked
  bool isRevoked({
    SignaturePacket? signature,
    final DateTime? date,
  }) {
    if (revocationSignatures.isNotEmpty) {
      for (var revocation in revocationSignatures) {
        if (signature == null || revocation.issuerKeyID.keyID == signature.issuerKeyID.keyID) {
          if (revocation.verify(
            keyPacket,
            keyPacket.writeForSign(),
            date: date,
          )) {
            return true;
          }
        }
      }
    }
    return false;
  }

  PacketList toPacketList() => PacketList([
        keyPacket,
        ...revocationSignatures,
        ...directSignatures,
        ...users.map((user) => user.toPacketList()).expand((packet) => packet),
        ...subkeys.map((subkey) => subkey.toPacketList()).expand((packet) => packet),
      ]);
}
