// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

/// Implementation of the Modification Detection Code Packet (Tag 19)
/// See RFC 4880, section 5.14
/// .
/// The Modification Detection Code packet contains a SHA-1 hash of plaintext data, which is used to detect message modification.
/// It is only used with a Symmetrically Encrypted Integrity Protected Data packet.
/// The Modification Detection Code packet MUST be the last packet in the plaintext data that is encrypted
/// in the Symmetrically Encrypted Integrity Protected Data packet, and MUST appear in no other place.
class ModificationDetectionCodePacket extends ContainedPacket {
  final Uint8List digest;

  ModificationDetectionCodePacket(this.digest) : super(PacketTag.modificationDetectionCode);

  factory ModificationDetectionCodePacket.fromPacketData(final Uint8List bytes) =>
      ModificationDetectionCodePacket(bytes);

  @override
  Uint8List toPacketData() {
    return digest;
  }
}
