/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/packet/packet_list.dart';

import '../type/key.dart';
import 'base.dart';

/// OpenPGP public key class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PublicKey extends Base {
  PublicKey(super.packetList);

  factory PublicKey.fromArmored(final String armored) {
    final armor = Armor.decode(armored);
    if (armor.type != ArmorType.publicKey) {
      throw ArgumentError('Armored text not of public key type');
    }
    return PublicKey(PacketList.decode(armor.data));
  }

  @override
  String armor() => Armor.encode(ArmorType.publicKey, packetList.encode());

  @override
  KeyInterface get publicKey => this;
}
