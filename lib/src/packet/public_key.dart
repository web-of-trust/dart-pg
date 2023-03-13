// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:crypto/crypto.dart';

import '../crypto/math/byte_ext.dart';
import '../crypto/math/int_ext.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../helpers.dart';
import 'key/key_id.dart';
import 'key/key_params.dart';
import 'contained_packet.dart';
import 'key_packet.dart';

/// PublicKey represents an OpenPGP public key.
/// See RFC 4880, section 5.5.2.
class PublicKeyPacket extends ContainedPacket implements KeyPacket {
  static const keyVersion = 4;

  @override
  final int version = keyVersion;

  @override
  final DateTime creationTime;

  @override
  final int expirationDays;

  @override
  final KeyAlgorithm algorithm;

  @override
  final KeyParams publicParams;

  late final Uint8List _fingerprint;

  late final KeyID _keyID;

  PublicKeyPacket(
    this.creationTime,
    this.publicParams, {
    this.expirationDays = 0,
    this.algorithm = KeyAlgorithm.rsaEncryptSign,
  }) : super(PacketTag.publicKey) {
    _calculateFingerprintAndKeyID();
  }

  factory PublicKeyPacket.fromByteData(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number (3 or 4 or 5).
    final version = bytes[pos++];
    if (version != keyVersion) {
      throw UnsupportedError('Version $version of the key packet is unsupported.');
    }

    /// A four-octet number denoting the time that the key was created.
    final creationTime = bytes.sublist(pos, pos + 4).toDateTime();
    pos += 4;

    // A one-octet number denoting the public-key algorithm of this key.
    final algorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;

    /// A series of values comprising the key material.
    /// This is algorithm-specific and described in section XXXX.
    final KeyParams publicParams;
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        publicParams = RSAPublicParams.fromByteData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.elgamal:
        publicParams = ElGamalPublicParams.fromByteData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.dsa:
        publicParams = DSAPublicParams.fromByteData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdh:
        publicParams = ECDHPublicParams.fromByteData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdsa:
        publicParams = ECDSAPublicParams.fromByteData(bytes.sublist(pos));
        break;
      default:
        throw UnsupportedError('Unsupported PGP public key algorithm encountered');
    }
    return PublicKeyPacket(
      creationTime,
      publicParams,
      algorithm: algorithm,
    );
  }

  /// Computes and set the fingerprint of the key
  void _calculateFingerprintAndKeyID() {
    final toHash = writeForSign();
    _fingerprint = Uint8List.fromList(sha1.convert(toHash).bytes);
    _keyID = KeyID(_fingerprint.sublist(12, 20));
  }

  @override
  String get fingerprint => _fingerprint.toHexadecimal();

  @override
  KeyID get keyID => _keyID;

  @override
  bool get isEncrypted => false;

  @override
  bool get isDecrypted => true;

  @override
  bool get isSigningKey {
    return KeyPacket.isSigningAlgorithm(algorithm);
  }

  @override
  bool get isEncryptionKey {
    return KeyPacket.isEncryptionAlgorithm(algorithm);
  }

  @override
  PublicKeyPacket get publicKey => this;

  @override
  int get keyStrength {
    final keyParams = publicParams;
    if (keyParams is RSAPublicParams) {
      return keyParams.modulus.bitLength;
    }
    if (keyParams is DSAPublicParams) {
      return keyParams.prime.bitLength;
    }
    if (keyParams is ElGamalPublicParams) {
      return keyParams.prime.bitLength;
    }
    if (keyParams is ECPublicParams) {
      return keyParams.publicKey.parameters!.curve.fieldSize;
    }
    return -1;
  }

  @override
  Uint8List writeForSign() {
    final bytes = toByteData();
    return Uint8List.fromList([
      0x99,
      ...bytes.lengthInBytes.pack16(),
      ...bytes,
    ]);
  }

  @override
  Uint8List toByteData() {
    final keyData = publicParams.encode();
    return Uint8List.fromList([
      version,
      ...creationTime.toBytes(),
      algorithm.value,
      ...keyData,
    ]);
  }
}
