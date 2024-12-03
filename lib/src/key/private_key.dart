/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/common/config.dart';
import 'package:dart_pg/src/enum/aead_algorithm.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/enum/hash_algorithm.dart';
import 'package:dart_pg/src/key/base.dart';
import 'package:dart_pg/src/key/public_key.dart';
import 'package:dart_pg/src/key/subkey.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/packet.dart';
import 'package:dart_pg/src/type/private_key.dart';
import 'package:dart_pg/src/type/secret_key_packet.dart';

final class PrivateKey extends Base implements PrivateKeyInterface {
  PrivateKey(super.packetList);

  @override
  SecretKeyPacketInterface get keyPacket => super.keyPacket as SecretKeyPacketInterface;

  @override
  bool get isDecrypted => keyPacket.isDecrypted;

  @override
  bool get isEncrypted => keyPacket.isEncrypted;

  @override
  bool get aeadProtected => keyPacket.aeadProtected;

  @override
  HashAlgorithm get preferredHash => keyPacket.preferredHash;

  @override
  KeyInterface get publicKey {
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

  @override
  String armor() => Armor.encode(ArmorType.privateKey, packetList.encode());

  @override
  PrivateKeyInterface encrypt(
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('Passphrase are required for key encryption.');
    }
    if (!keyPacket.isDecrypted) {
      throw StateError('Private key must be decrypted before encrypting.');
    }

    AeadAlgorithm? aead;
    if (version == 6 && Config.aeadProtect) {
      aead = Config.preferredAead;
    }
    final subkeys = this.subkeys.map((subkey) {
      final index = this.subkeys.indexOf(subkey);
      final subkeyPass = (index < subkeyPassphrases.length) ? subkeyPassphrases.elementAt(index) : passphrase;
      if (subkeyPass.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
        final keyPacket = (subkey.keyPacket as SecretSubkeyPacket);
        return Subkey(
          this,
          keyPacket.encrypt(
            subkeyPass,
            Config.preferredSymmetric,
            aead,
          ),
          revocationSignatures: subkey.revocationSignatures.toList(),
          bindingSignatures: subkey.bindingSignatures.toList(),
        );
      } else {
        return subkey;
      }
    });

    return PrivateKey(PacketList([
      keyPacket.encrypt(
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
  PrivateKeyInterface decrypt(
    String passphrase, [
    Iterable<String> subkeyPassphrases = const [],
  ]) {
    if (passphrase.isEmpty) {
      throw ArgumentError('Passphrase are required for key decryption,');
    }
    final subkeys = this.subkeys.map((subkey) {
      final index = this.subkeys.indexOf(subkey);
      final subkeyPass = (index < subkeyPassphrases.length) ? subkeyPassphrases.elementAt(index) : passphrase;
      if (subkeyPass.isNotEmpty && subkey.keyPacket is SecretSubkeyPacket) {
        final keyPacket = (subkey.keyPacket as SecretSubkeyPacket);
        return Subkey(
          this,
          keyPacket.decrypt(subkeyPass),
          revocationSignatures: subkey.revocationSignatures.toList(),
          bindingSignatures: subkey.bindingSignatures.toList(),
        );
      } else {
        return subkey;
      }
    });
    return PrivateKey(PacketList([
      keyPacket.decrypt(passphrase),
      ...revocationSignatures,
      ...directSignatures,
      ...users.map((user) => user.packetList).expand((packet) => packet),
      ...subkeys.map((subkey) => subkey.packetList).expand((packet) => packet),
    ]));
  }
}
