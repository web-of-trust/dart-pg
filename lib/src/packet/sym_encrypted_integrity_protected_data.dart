// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'contained_packet.dart';

/// Implementation of the Sym. Encrypted Integrity Protected Data Packet (Tag 18)
/// See RFC 4880, section 5.13.
///
/// The Symmetrically Encrypted Integrity Protected Data packet is a variant of the Symmetrically Encrypted Data packet.
/// It is a new feature created for OpenPGP that addresses the problem of detecting a modification to encrypted data.
/// It is used in combination with a Modification Detection Code packet.
class SymEncryptedIntegrityProtectedData extends ContainedPacket {
  static const tag = PacketTag.symEncryptedIntegrityProtectedData;

  final int version;

  final Uint8List encrypted;

  SymEncryptedIntegrityProtectedData(this.version, this.encrypted);

  factory SymEncryptedIntegrityProtectedData.fromPacketData(final Uint8List bytes) =>
      SymEncryptedIntegrityProtectedData(bytes[0], bytes.sublist(1));

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([version, ...encrypted]);
  }
}
