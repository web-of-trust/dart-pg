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
abstract class SignaturePacketInterface extends PacketInterface {
  int get version;

  SignatureType get signatureType;

  KeyAlgorithm get keyAlgorithm;

  HashAlgorithm get hashAlgorithm;

  Iterable<SubpacketInterface> get hashedSubpackets;

  Iterable<SubpacketInterface> get unhashedSubpackets;

  Uint8List get signatureData;

  Uint8List get signedHashValue;

  Uint8List get salt;

  Uint8List get signature;

  DateTime? get creationTime;

  DateTime? get expirationTime;

  int get keyExpirationTime;

  Uint8List get issuerKeyID;

  Uint8List get issuerFingerprint;

  bool get isPrimaryUserID;

  bool get isCertification;

  bool get isCertRevocation;

  bool get isDirectKey;

  bool get isKeyRevocation;

  bool get isSubkeyBinding;

  bool get isSubkeyRevocation;

  T? getSubpacket<T extends SubpacketInterface>();

  bool isExpired([final DateTime? time]);

  bool verify(
    final KeyPacketInterface verifyKey,
    final Uint8List dataToVerify, [
    final DateTime? time,
  ]);
}
