/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/api.dart';

import '../type/encrypted_data_packet.dart';
import '../type/packet_list.dart';
import '../common/config.dart';
import '../common/helpers.dart';
import '../cryptor/symmetric/buffered_cipher.dart';
import '../enum/symmetric_algorithm.dart';
import 'base_packet.dart';

/// Implementation of the Symmetrically Encrypted Data (SED) Packet - Type 9
/// The encrypted contents will consist of more OpenPGP packets.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SymEncryptedDataPacket extends BasePacket
    implements EncryptedDataPacketInterface {
  @override
  final Uint8List encrypted;

  @override
  final PacketListInterface? packets;

  SymEncryptedDataPacket(
    this.encrypted, {
    this.packets,
  }) : super(PacketType.symEncryptedData);

  factory SymEncryptedDataPacket.fromBytes(
    final Uint8List bytes,
  ) =>
      SymEncryptedDataPacket(bytes);

  factory SymEncryptedDataPacket.encryptPackets(
    final Uint8List key,
    final PacketListInterface packets, [
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    final cipher = BufferedCipher(symmetric.cfbCipherEngine)
      ..init(
        true,
        ParametersWithIV(
          KeyParameter(key),
          Uint8List(symmetric.blockSize),
        ),
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
  get data => encrypted;

  @override
  decrypt(
    final Uint8List key, [
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    if (!Config.allowUnauthenticated) {
      throw AssertionError(
        'Message is not authenticated.',
      );
    }
    final blockSize = symmetric.blockSize;
    final cipher = BufferedCipher(symmetric.cfbCipherEngine)
      ..init(
        false,
        ParametersWithIV(
          KeyParameter(key),
          encrypted.sublist(2, blockSize + 2),
        ),
      );
    return SymEncryptedDataPacket(
      encrypted,
      packets: PacketList.decode(
        cipher.process(encrypted.sublist(blockSize + 2)),
      ),
    );
  }
}
