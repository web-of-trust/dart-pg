/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/symmetric_algorithm.dart';
import 'packet_list.dart';

/// Encrypted data packet interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class EncryptedDataPacketInterface {
  /// Encrypted data
  Uint8List get encrypted;

  /// Decrypted packets contained within.
  PacketListInterface? get packets;

  /// Decrypt the encrypted data contained in the packet.
  EncryptedDataPacketInterface decrypt(
    final Uint8List key, {
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  });
}
