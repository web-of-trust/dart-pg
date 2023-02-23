// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../crypto/symmetric/base_cipher.dart';
import '../enums.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'packet_list.dart';

/// SymmetricallyEncryptedData packet (tag 9) represents a symmetrically encrypted byte string.
/// The encrypted contents will consist of more OpenPGP packets.
/// See RFC 4880, sections 5.7 and 5.13.
class SymmetricallyEncryptedDataPacket extends ContainedPacket {
  /// Encrypted secret-key data
  final Uint8List encrypted;

  /// Decrypted packets contained within.
  final PacketList? packets;

  SymmetricallyEncryptedDataPacket(this.encrypted, {this.packets}) : super(PacketTag.symmetricallyEncryptedData);

  factory SymmetricallyEncryptedDataPacket.fromPacketData(final Uint8List bytes) =>
      SymmetricallyEncryptedDataPacket(bytes);

  factory SymmetricallyEncryptedDataPacket.encryptPackets(
    final SymmetricAlgorithm sessionKeySymmetric,
    final Uint8List key,
    final PacketList packets,
  ) {
    final cipher = BufferedCipher(sessionKeySymmetric.cipherEngine)
      ..init(
        true,
        ParametersWithIV(KeyParameter(key), Uint8List(sessionKeySymmetric.blockSize)),
      );
    final prefix = cipher.process(Helper.generatePrefix(sessionKeySymmetric));

    cipher.init(
      true,
      ParametersWithIV(KeyParameter(key), prefix.sublist(2)),
    );
    return SymmetricallyEncryptedDataPacket(
      cipher.process(packets.packetEncode()),
      packets: packets,
    );
  }

  @override
  Uint8List toPacketData() {
    return encrypted;
  }

  /// Encrypt the symmetrically-encrypted packet data
  SymmetricallyEncryptedDataPacket encrypt(final SymmetricAlgorithm sessionKeySymmetric, final Uint8List key) {
    if (packets != null && packets!.isNotEmpty) {
      return SymmetricallyEncryptedDataPacket.encryptPackets(sessionKeySymmetric, key, packets!);
    }
    return this;
  }

  /// Decrypt the symmetrically-encrypted packet data
  SymmetricallyEncryptedDataPacket decrypt(final SymmetricAlgorithm sessionKeySymmetric, final Uint8List key) {
    final blockSize = sessionKeySymmetric.blockSize;
    final cipher = BufferedCipher(sessionKeySymmetric.cipherEngine)
      ..init(false, ParametersWithIV(KeyParameter(key), encrypted.sublist(2, blockSize + 2)));
    return SymmetricallyEncryptedDataPacket(
      encrypted,
      packets: PacketList.packetDecode(cipher.process(encrypted.sublist(blockSize + 2))),
    );
  }
}
