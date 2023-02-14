// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:crypto/crypto.dart';

import '../enums.dart';
import '../helpers.dart';
import 'key/dsa_public_params.dart';
import 'key/ec_public_params.dart';
import 'key/ecdh_public_params.dart';
import 'key/ecdsa_public_params.dart';
import 'key/elgamal_public_params.dart';
import 'key/key_id.dart';
import 'key/key_params.dart';
import 'key/rsa_public_params.dart';
import 'contained_packet.dart';
import 'key_packet.dart';

/// PublicKey represents an OpenPGP public key.
/// See RFC 4880, section 5.5.2.
class PublicKeyPacket extends ContainedPacket implements KeyPacket {
  @override
  final int version;

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
    this.version,
    this.creationTime,
    this.publicParams, {
    this.expirationDays = 0,
    this.algorithm = KeyAlgorithm.rsaEncryptSign,
    super.tag = PacketTag.publicKey,
  }) {
    if (version != 4 && version != 5) {
      throw UnsupportedError('Version $version of the key packet is unsupported.');
    }
    _calculateFingerprintAndKeyID();
  }

  factory PublicKeyPacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number (4 or 5).
    final version = bytes[pos++];
    if (version != 4 && version != 5) {
      throw UnsupportedError('Version $version of the key packet is unsupported.');
    }

    /// A four-octet number denoting the time that the key was created.
    final creationTime = bytes.sublist(pos, pos + 4).toDateTime();
    pos += 4;

    // A one-octet number denoting the public-key algorithm of this key.
    final algorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;
    if (version == 5) {
      /// - A four-octet scalar octet count for the following key material.
      pos += 4;
    }

    /// A series of values comprising the key material.
    /// This is algorithm-specific and described in section XXXX.
    final KeyParams publicParams;
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        publicParams = RSAPublicParams.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.elgamal:
        publicParams = ElGamalPublicParams.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.dsa:
        publicParams = DSAPublicParams.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdh:
        publicParams = ECDHPublicParams.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdsa:
        publicParams = ECDSAPublicParams.fromPacketData(bytes.sublist(pos));
        break;
      default:
        throw UnsupportedError('Unknown PGP public key algorithm encountered');
    }
    return PublicKeyPacket(
      version,
      creationTime,
      publicParams,
      algorithm: algorithm,
    );
  }

  /// Computes and set the fingerprint of the key
  void _calculateFingerprintAndKeyID() {
    final toHash = writeForHash();
    if (version == 4) {
      _fingerprint = Uint8List.fromList(sha1.convert(toHash).bytes);
      _keyID = KeyID(_fingerprint.sublist(12, 20));
    } else {
      _fingerprint = Uint8List.fromList(sha256.convert(toHash).bytes);
      _keyID = KeyID(_fingerprint.sublist(0, 8));
    }
  }

  @override
  String get fingerprint => _fingerprint.toHexadecimal();

  @override
  KeyID get keyID => _keyID;

  @override
  int get keyStrength {
    final keyParams = publicParams;
    if (keyParams is RSAPublicParams) {
      return keyParams.modulus.bitLength;
    }
    if (keyParams is DSAPublicParams) {
      return keyParams.primeP.bitLength;
    }
    if (keyParams is ElGamalPublicParams) {
      return keyParams.primeP.bitLength;
    }
    if (keyParams is ECPublicParams) {
      return keyParams.publicKey.parameters!.curve.fieldSize;
    }
    return -1;
  }

  @override
  Uint8List writeForHash() {
    final packetData = toPacketData();
    return Uint8List.fromList([
      (version == 5) ? 0x9a : 0x99,
      ...(version == 5) ? packetData.length.pack32() : packetData.length.pack16(),
      ...packetData,
    ]);
  }

  @override
  Uint8List toPacketData() {
    final keyData = publicParams.encode();
    return Uint8List.fromList([
      version,
      ...creationTime.toBytes(),
      algorithm.value,
      ...(version == 5) ? keyData.length.pack32() : [],
      ...keyData,
    ]);
  }
}
