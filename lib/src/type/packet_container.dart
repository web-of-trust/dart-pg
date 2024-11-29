/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'packet_list.dart';

/// Packet container interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class PacketContainerInterface {
  /// Get packet list
  PacketListInterface get packetList;
}
