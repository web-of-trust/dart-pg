// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

/// SymmetricallyEncryptedData represents a symmetrically encrypted byte string.
/// The encrypted contents will consist of more OpenPGP packets.
/// See RFC 4880, sections 5.7 and 5.13.
class SymmetricallyEncryptedDataPacket extends ContainedPacket {
  final Uint8List encrypted;

  SymmetricallyEncryptedDataPacket(this.encrypted) : super(PacketTag.symmetricallyEncryptedData);

  factory SymmetricallyEncryptedDataPacket.fromPacketData(final Uint8List bytes) =>
      SymmetricallyEncryptedDataPacket(bytes);

  @override
  Uint8List toPacketData() {
    return encrypted;
  }
}
