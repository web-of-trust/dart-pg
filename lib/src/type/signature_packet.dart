/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../enum/hash_algorithm.dart';
import '../enum/key_algorithm.dart';
import '../enum/signature_type.dart';
import 'key_packet.dart';
import 'packet.dart';
import 'subpacket.dart';

/// Signature packet interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SignaturePacketInterface implements PacketInterface {
  /// Get version
  int get version;

  /// Get signature type
  SignatureType get signatureType;

  /// Get key algorithm
  KeyAlgorithm get keyAlgorithm;

  /// Get hash algorithm
  HashAlgorithm get hashAlgorithm;

  /// Get hashed subpackets
  List<SubpacketInterface> get hashedSubpackets;

  /// Get unhashed subpackets
  List<SubpacketInterface> get unhashedSubpackets;

  /// Get signature data
  Uint8List get signatureData;

  /// Get signed hash value
  Uint8List get signedHashValue;

  /// Get salt value
  Uint8List get salt;

  /// Get signature
  Uint8List get signature;

  /// Get signature creation time
  DateTime get creationTime;

  /// Get signature expiration time
  DateTime? get expirationTime;

  /// Get key expiration time
  int get keyExpirationTime;

  /// Get issuer key ID
  Uint8List get issuerKeyID;

  /// Get issuer key fingerprint
  Uint8List get issuerFingerprint;

  /// Return is primary user ID
  bool get isPrimaryUserID;

  /// Return is certification
  bool get isCertification;

  /// Return is revocation certification
  bool get isCertRevocation;

  /// Return is direct key
  bool get isDirectKey;

  /// Return is key revocation
  bool get isKeyRevocation;

  /// Return is subkey binding
  bool get isSubkeyBinding;

  /// Return is subkey revocation
  bool get isSubkeyRevocation;

  /// Get subpacket
  T? getSubpacket<T extends SubpacketInterface>();

  /// Verify signature expiration date.
  /// Use the given date for verification instead of the current time.
  bool isExpired([final DateTime? time]);

  /// Verify the signature packet.
  bool verify(
    final KeyPacketInterface verifyKey,
    final Uint8List dataToVerify, [
    final DateTime? time,
  ]);
}
