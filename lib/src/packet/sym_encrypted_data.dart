// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../crypto/symmetric/base_cipher.dart';
import '../enum/packet_tag.dart';
import '../enum/symmetric_algorithm.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'packet_list.dart';

/// SymEncryptedData packet (tag 9) represents a Symmetrically Encrypted Data packet.
/// The encrypted contents will consist of more OpenPGP packets.
///
/// See RFC 4880, sections 5.7 and 5.13.
/// The Symmetrically Encrypted Data packet contains data encrypted with a symmetric-key algorithm.
/// When it has been decrypted, it contains other packets (usually a literal data packet or compressed data packet,
/// but in theory other Symmetrically Encrypted Data packets or sequences of packets that form whole OpenPGP messages).
class SymEncryptedDataPacket extends ContainedPacket {
  /// Encrypted secret-key data
  final Uint8List encrypted;

  /// Decrypted packets contained within.
  final PacketList? packets;

  SymEncryptedDataPacket(this.encrypted, {this.packets}) : super(PacketTag.symEncryptedData);

  factory SymEncryptedDataPacket.fromByteData(final Uint8List bytes) => SymEncryptedDataPacket(bytes);

  static Future<SymEncryptedDataPacket> encryptPackets(
    final Uint8List key,
    final PacketList packets, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes256,
  }) async {
    final cipher = BufferedCipher(symmetric.cipherEngine)
      ..init(
        true,
        ParametersWithIV(KeyParameter(key), Uint8List(symmetric.blockSize)),
      );
    final prefix = cipher.process(Helper.generatePrefix(symmetric));

    cipher.init(
      true,
      ParametersWithIV(KeyParameter(key), prefix.sublist(2)),
    );
    return SymEncryptedDataPacket(
      Uint8List.fromList([
        ...prefix,
        ...cipher.process(packets.encode()),
      ]),
      packets: packets,
    );
  }

  @override
  Uint8List toByteData() {
    return encrypted;
  }

  /// Encrypt the symmetrically-encrypted packet data
  Future<SymEncryptedDataPacket> encrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes256,
  }) async {
    if (packets != null && packets!.isNotEmpty) {
      return SymEncryptedDataPacket.encryptPackets(key, packets!, symmetric: symmetric);
    }
    return this;
  }

  /// Decrypt the symmetrically-encrypted packet data
  Future<SymEncryptedDataPacket> decrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes256,
    final bool allowUnauthenticatedMessages = false,
  }) async {
    if (!allowUnauthenticatedMessages) {
      throw StateError('Message is not authenticated.');
    }
    final blockSize = symmetric.blockSize;
    final cipher = BufferedCipher(symmetric.cipherEngine)
      ..init(
        false,
        ParametersWithIV(KeyParameter(key), encrypted.sublist(2, blockSize + 2)),
      );
    return SymEncryptedDataPacket(
      encrypted,
      packets: PacketList.packetDecode(cipher.process(encrypted.sublist(blockSize + 2))),
    );
  }
}
