// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import 'key/key_id.dart';
import 'contained_packet.dart';
import 'key/key_params.dart';
import 'public_key.dart';

export 'public_key.dart';
export 'public_subkey.dart';
export 'secret_key.dart';
export 'secret_subkey.dart';

abstract class KeyPacket implements ContainedPacket {
  int get version;

  DateTime get creationTime;

  int get expirationDays;

  KeyAlgorithm get algorithm;

  KeyParams get publicParams;

  String get fingerprint;

  KeyID get keyID;

  int get keyStrength;

  bool get isEncrypted;

  bool get isDecrypted;

  bool get isSigningKey;

  bool get isEncryptionKey;

  PublicKeyPacket get publicKey;

  Uint8List writeForSign();

  static isSigningAlgorithm(KeyAlgorithm algorithm) {
    switch (algorithm) {
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.elgamal:
      case KeyAlgorithm.ecdh:
      case KeyAlgorithm.diffieHellman:
      case KeyAlgorithm.aedh:
        return false;
      default:
        return true;
    }
  }

  static isEncryptionAlgorithm(KeyAlgorithm algorithm) {
    switch (algorithm) {
      case KeyAlgorithm.rsaSign:
      case KeyAlgorithm.dsa:
      case KeyAlgorithm.ecdsa:
      case KeyAlgorithm.eddsa:
      case KeyAlgorithm.aedsa:
        return false;
      default:
        return true;
    }
  }
}
