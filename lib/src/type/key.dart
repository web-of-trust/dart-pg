/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/key_algorithm.dart';
import 'armorable.dart';
import 'key_packet.dart';
import 'packet_container.dart';
import 'signature_packet.dart';
import 'subkey.dart';
import 'user.dart';

/// Transferable key interface
/// That represents a key packet, the relevant signatures, users and subkeys.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class KeyInterface implements ArmorableInterface, PacketContainerInterface {
  KeyPacketInterface get keyPacket;

  KeyInterface get publicKey;

  int get version;

  DateTime? get creationTime;

  DateTime? get expirationTime;

  KeyAlgorithm get keyAlgorithm;

  Uint8List get fingerprint;

  Uint8List get keyID;

  int get keyStrength;

  Iterable<SignaturePacketInterface> get revocationSignatures;

  Iterable<SignaturePacketInterface> get directSignatures;

  Iterable<UserInterface> get users;

  Iterable<SubkeyInterface> get subkeys;
}
