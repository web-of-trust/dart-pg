/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/key_algorithm.dart';
import 'key_material.dart';
import 'packet.dart';

/// Key packet interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class KeyPacketInterface implements PacketInterface {
  /// Get key version
  int get keyVersion;

  /// Get creation time
  DateTime get creationTime;

  /// Get key algorithm
  KeyAlgorithm get keyAlgorithm;

  /// Get fingerprint
  Uint8List get fingerprint;

  /// Get key ID
  Uint8List get keyID;

  /// Get key strength
  int get keyStrength;

  /// Return key packet is subkey
  bool get isSubkey;

  /// Is signing key
  bool get isSigningKey;

  /// Is encryption key
  bool get isEncryptionKey;

  /// Is version 6 key
  bool get isV6Key;

  /// Get bytes for sign
  Uint8List get signBytes;

  /// Get key material
  KeyMaterialInterface get keyMaterial;
}
