/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/armor.dart';
import '../enum/armor_type.dart';
import '../packet/base_packet.dart';
import '../type/key.dart';
import 'base_key.dart';

/// OpenPGP public key class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class PublicKey extends BaseKey {
  PublicKey(super.packetList);

  /// Read public key from armored string
  factory PublicKey.fromArmored(final String armored) {
    final armor = Armor.decode(armored).assertType(ArmorType.publicKey);
    return PublicKey(PacketList.decode(armor.data));
  }

  /// Read public keys from armored string
  /// Return one or multiple key objects
  static Iterable<KeyInterface> readPublicKeys(final String armored) {
    final armor = Armor.decode(armored).assertType(ArmorType.publicKey);
    final publicKeys = <KeyInterface>[];
    final packetList = PacketList.decode(armor.data);
    final indexes = packetList.indexOfTypes([PacketType.publicKey]);
    for (var i = 0; i < indexes.length; i++) {
      if (indexes.asMap().containsKey(i + 1)) {
        publicKeys.add(
          PublicKey(
            PacketList(
              packetList.packets.sublist(indexes[i], indexes[i + 1]),
            ),
          ),
        );
      } else {
        publicKeys.add(
          PublicKey(
            PacketList(
              packetList.packets.sublist(indexes[i]),
            ),
          ),
        );
      }
    }
    return publicKeys;
  }

  /// Armor multiple public key.
  static String armorPublicKeys(
    final Iterable<KeyInterface> keys,
  ) =>
      Armor.encode(
          ArmorType.publicKey,
          Uint8List.fromList(keys
              .map(
                (key) => key.publicKey.packetList,
              )
              .expand(
                (packet) => packet.encode(),
              )
              .toList()));

  @override
  armor() => Armor.encode(ArmorType.publicKey, packetList.encode());

  @override
  get publicKey => this;
}
