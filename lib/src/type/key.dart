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
abstract interface class KeyInterface implements ArmorableInterface, PacketContainerInterface {
  /// Return key packet
  KeyPacketInterface get keyPacket;

  /// Return key as public key
  KeyInterface get publicKey;

  /// Return key version
  int get version;

  /// Get creation time
  DateTime get creationTime;

  /// Return the expiration time of the key or null if key does not expire.
  DateTime? get expirationTime;

  /// Get key algorithm
  KeyAlgorithm get keyAlgorithm;

  /// Get fingerprint
  Uint8List get fingerprint;

  /// Get key ID
  Uint8List get keyID;

  /// Get key strength
  int get keyStrength;

  /// Get revocation signatures
  List<SignaturePacketInterface> get revocationSignatures;

  /// Get direct signatures
  List<SignaturePacketInterface> get directSignatures;

  /// Get users
  List<UserInterface> get users;

  /// Get subkeys
  List<SubkeyInterface> get subkeys;

  /// Get encryption key packet
  KeyPacketInterface? getEncryptionKeyPacket([Uint8List? keyID]);

  /// Check if the key is revoked
  bool isRevoked({
    final KeyInterface? verifyKey,
    final SignaturePacketInterface? certificate,
    final DateTime? time,
  });

  /// Check if the key is certified
  bool isCertified({
    final KeyInterface? verifyKey,
    final SignaturePacketInterface? certificate,
    final DateTime? time,
  });

  /// Verify the key.
  /// Check for existence and validity of direct & user signature.
  bool verify([final String userID = '', final DateTime? time]);
}
