/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../common/armor.dart';
import '../enum/armor_type.dart';
import '../type/armorable.dart';
import '../type/packet_container.dart';
import '../type/packet_list.dart';

export 'cleartext_message.dart';
export 'encrypted_message.dart';
export 'literal_message.dart';
export 'signature.dart';
export 'signed_message.dart';
export 'verification.dart';

/// Base abstract OpenPGP message class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class BaseMessage
    implements ArmorableInterface, PacketContainerInterface {
  @override
  final PacketListInterface packetList;

  BaseMessage(this.packetList);

  @override
  armor() => Armor.encode(ArmorType.message, packetList.encode());
}
