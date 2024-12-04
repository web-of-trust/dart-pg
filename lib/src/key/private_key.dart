/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/common/config.dart';
import 'package:dart_pg/src/enum/aead_algorithm.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/enum/key_version.dart';
import 'package:dart_pg/src/key/base.dart';
import 'package:dart_pg/src/key/public_key.dart';
import 'package:dart_pg/src/key/subkey.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/type/packet.dart';
import 'package:dart_pg/src/type/private_key.dart';
import 'package:dart_pg/src/type/secret_key_packet.dart';

final class PrivateKey extends BaseKey implements PrivateKeyInterface {
  PrivateKey(super.packetList);

  @override
  get secretKeyPacket => super.keyPacket as SecretKeyPacketInterface;

  @override
  get isDecrypted => secretKeyPacket.isDecrypted;

  @override
  get isEncrypted => secretKeyPacket.isEncrypted;

  @override
  get aeadProtected => secretKeyPacket.aeadProtected;

  @override
  get preferredHash => secretKeyPacket.preferredHash;

  @override
  get publicKey {
    final packets = <PacketInterface>[];
    for (final packet in packetList) {
      switch (packet.type) {
        case PacketType.secretKey:
          if (packet is SecretKeyPacket) {
            packets.add(packet.publicKey);
          }
          break;
        case PacketType.secretSubkey:
          if (packet is SecretSubkeyPacket) {
            packets.add(packet.publicKey);
          }
          break;
        default:
          packets.add(packet);
      }
    }
    return PublicKey(PacketList(packets));
  }

  /// Reads an armored OpenPGP private key and returns a PrivateKey object
  factory PrivateKey.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.privateKey) {
      throw ArgumentError('Armored text not of private key type');
    }
    return PrivateKey(PacketList.decode(armor.data));
  }

  @override
  armor() => Armor.encode(ArmorType.privateKey, packetList.encode());

  @override
  encrypt(
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('Passphrase are required for key encryption.');
    }
    if (!secretKeyPacket.isDecrypted) {
      throw StateError('Private key must be decrypted before encrypting.');
    }

    AeadAlgorithm? aead;
    if (version == KeyVersion.v6.value && Config.aeadProtect) {
      aead = Config.preferredAead;
    }
    final subkeys = this.subkeys.map((subkey) {
      final index = this.subkeys.indexOf(subkey);
      final subkeyPass = subkeyPassphrases.elementAtOrNull(index) ?? passphrase;
      if (subkeyPass.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
        final keyPacket = (subkey.keyPacket as SecretSubkeyPacket);
        return Subkey(
          this,
          keyPacket.encrypt(
            subkeyPass,
            Config.preferredSymmetric,
            aead,
          ),
          revocationSignatures: subkey.revocationSignatures,
          bindingSignatures: subkey.bindingSignatures,
        );
      } else {
        return subkey;
      }
    });

    return PrivateKey(PacketList([
      secretKeyPacket.encrypt(
        passphrase,
        Config.preferredSymmetric,
        aead,
      ),
      ...revocationSignatures,
      ...directSignatures,
      ...users.map((user) => user.packetList).expand((packet) => packet),
      ...subkeys.map((subkey) => subkey.packetList).expand((packet) => packet),
    ]));
  }

  @override
  decrypt(
    String passphrase, [
    Iterable<String> subkeyPassphrases = const [],
  ]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('Passphrase are required for key decryption,');
    }
    final subkeys = this.subkeys.map((subkey) {
      final index = this.subkeys.indexOf(subkey);
      final subkeyPass = subkeyPassphrases.elementAtOrNull(index) ?? passphrase;
      if (subkeyPass.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
        final keyPacket = (subkey.keyPacket as SecretSubkeyPacket);
        return Subkey(
          this,
          keyPacket.decrypt(subkeyPass),
          revocationSignatures: subkey.revocationSignatures,
          bindingSignatures: subkey.bindingSignatures,
        );
      } else {
        return subkey;
      }
    });
    return PrivateKey(PacketList([
      secretKeyPacket.decrypt(passphrase),
      ...revocationSignatures,
      ...directSignatures,
      ...users.map((user) => user.packetList).expand((packet) => packet),
      ...subkeys.map((subkey) => subkey.packetList).expand((packet) => packet),
    ]));
  }
}
