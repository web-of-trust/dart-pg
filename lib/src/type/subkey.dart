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
abstract interface class SubkeyInterface implements PacketContainerInterface {
  /// Get main key
  KeyInterface get mainKey;

  /// Get key packet
  SubkeyPacketInterface get keyPacket;

  /// Return key version
  int get version;

  /// Get creation time
  DateTime get creationTime;

  /// Get the expiration time of the subkey or null if subkey does not expire.
  DateTime? get expirationTime;

  /// Get key algorithm
  KeyAlgorithm get keyAlgorithm;

  /// Get fingerprint
  Uint8List get fingerprint;

  /// Get key ID
  Uint8List get keyID;

  /// Get key strength
  int get keyStrength;

  /// Return subkey is signing or verification key
  bool get isSigningKey;

  /// Return subkey is encryption or decryption key
  bool get isEncryptionKey;

  /// Get revocation signatures
  List<SignaturePacketInterface> get revocationSignatures;

  /// Get binding signatures
  List<SignaturePacketInterface> get bindingSignatures;

  /// Check if the subkey is revoked
  bool isRevoked([final DateTime? time]);

  /// Verify subkey.
  /// Check for existence and validity of binding signature.
  bool verify([final DateTime? time]);
}
