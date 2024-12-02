/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/key_algorithm.dart';
import 'key.dart';
import 'packet_container.dart';
import 'signature_packet.dart';
import 'subkey_packet.dart';

/// Subkey interface
/// That represents a subkey packet and the relevant signatures.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class SubkeyInterface implements PacketContainerInterface {
  KeyInterface get mainKey;

  SubkeyPacketInterface get keyPacket;

  int get version;

  DateTime get creationTime;

  DateTime? get expirationTime;

  KeyAlgorithm get keyAlgorithm;

  Uint8List get fingerprint;

  Uint8List get keyID;

  int get keyStrength;

  bool get isSigningKey;

  bool get isEncryptionKey;

  Iterable<SignaturePacketInterface> get revocationSignatures;

  Iterable<SignaturePacketInterface> get bindingSignatures;

  bool isRevoked([final DateTime? time]);

  bool verify([final DateTime? time]);
}
