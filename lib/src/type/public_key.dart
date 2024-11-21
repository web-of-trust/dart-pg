// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enum/packet_tag.dart';
import '../enum/armor_type.dart';
import '../packet/packet_list.dart';
import '../packet/key_packet.dart';
import 'key.dart';

/// Class that represents an OpenPGP Public Key
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PublicKey extends Key {
  PublicKey(
    final PublicKeyPacket keyPacket, {
    super.revocationSignatures,
    super.directSignatures,
    super.users,
    super.subkeys,
  }) : super(keyPacket);

  factory PublicKey.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.publicKey) {
      throw ArgumentError('Armored text not of public key type');
    }
    return PublicKey.fromPacketList(PacketList.packetDecode(armor.data));
  }

  factory PublicKey.fromPacketList(final PacketList packetList) {
    final keyRecord = Key.readPacketList(packetList);
    if (keyRecord.keyPacket is! PublicKeyPacket) {
      throw StateError('Key packet not of secret key type');
    }
    return PublicKey(
      keyRecord.keyPacket as PublicKeyPacket,
      revocationSignatures: keyRecord.revocationSignatures,
      directSignatures: keyRecord.directSignatures,
      users: keyRecord.users,
      subkeys: keyRecord.subkeys,
    );
  }

  static List<PublicKey> readPublicKeys(String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.publicKey) {
      throw ArgumentError('Armored text not of public key type');
    }
    final publicKeys = <PublicKey>[];
    final packetList = PacketList.packetDecode(armor.data);
    final indexes = packetList.indexOfTags([PacketTag.publicKey]);
    for (var i = 0; i < indexes.length; i++) {
      if (indexes.asMap().containsKey(i + 1)) {
        publicKeys.add(
          PublicKey.fromPacketList(
            PacketList(
              packetList.packets.sublist(indexes[i], indexes[i + 1]),
            ),
          ),
        );
      }
    }
    return publicKeys;
  }

  @override
  PublicKeyPacket get keyPacket => super.keyPacket as PublicKeyPacket;

  @override
  PublicKey get toPublic => this;

  @override
  String armor() => Armor.encode(ArmorType.publicKey, toPacketList().encode());

  Future<PublicKeyPacket> getEncryptionKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) async {
    if (!await verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort(
      (a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime),
    );
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (subkey.isEncryptionKey && await subkey.verify(date: date)) {
          return subkey.keyPacket.publicKey;
        }
      }
    }
    if (isSigningKey || (keyID.isNotEmpty && keyID != keyPacket.keyID.toString())) {
      throw StateError('Could not find valid encryption key packet.');
    }
    return keyPacket.publicKey;
  }

  Future<PublicKeyPacket> getVerificationKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) async {
    if (!await verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort(
      (a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime),
    );
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (!subkey.isEncryptionKey && await subkey.verify(date: date)) {
          return subkey.keyPacket as PublicKeyPacket;
        }
      }
    }
    if (isEncryptionKey || (keyID.isNotEmpty && keyID != keyPacket.keyID.toString())) {
      throw StateError('Could not find valid verification key packet.');
    }
    return keyPacket;
  }
}
