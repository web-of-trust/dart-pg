/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/type/armorable.dart';
import 'package:dart_pg/src/type/packet_container.dart';
import 'package:dart_pg/src/type/packet_list.dart';

/// Base abstract OpenPGP message class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class BaseMessage implements ArmorableInterface, PacketContainerInterface {
  @override
  final PacketListInterface packetList;

  BaseMessage(this.packetList);

  @override
  armor() => Armor.encode(ArmorType.message, packetList.encode());
}
