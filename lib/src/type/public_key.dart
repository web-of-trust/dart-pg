// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../armor/armor.dart';
import '../enum/armor_type.dart';
import '../packet/packet_list.dart';
import '../packet/key_packet.dart';
import 'key.dart';
import 'key_reader.dart';

/// Class that represents an OpenPGP Public Key
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

  PublicKeyPacket getEncryptionKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) {
    if (!verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort((a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime));
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (subkey.isEncryptionKey && subkey.verify(date: date)) {
          return subkey.keyPacket.publicKey;
        }
      }
    }
    if (isSigningKey || (keyID.isNotEmpty && keyID != keyPacket.keyID.toString())) {
      throw StateError('Could not find valid encryption key packet.');
    }
    return keyPacket.publicKey;
  }

  PublicKeyPacket getVerificationKeyPacket({
    final String keyID = '',
    final DateTime? date,
  }) {
    if (!verifyPrimaryKey(date: date)) {
      throw StateError('Primary key is invalid');
    }
    subkeys.sort((a, b) => b.keyPacket.creationTime.compareTo(a.keyPacket.creationTime));
    for (final subkey in subkeys) {
      if (keyID.isEmpty || keyID == subkey.keyID.toString()) {
        if (!subkey.isEncryptionKey && subkey.verify(date: date)) {
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
