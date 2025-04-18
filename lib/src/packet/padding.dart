/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/helpers.dart';
import 'base_packet.dart';

/// Implementation of the Padding (PADDING) Packet - Type 21.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class PaddingPacket extends BasePacket {
  static const paddingMin = 16;
  static const paddingMax = 32;

  final Uint8List padding;

  PaddingPacket(this.padding) : super(PacketType.marker);

  factory PaddingPacket.createPadding(final int lengh) {
    assert(paddingMin <= lengh && lengh <= paddingMax);
    return PaddingPacket(Helper.randomBytes(lengh));
  }

  @override
  get data => padding;
}
