// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';
import 'package:crypto/crypto.dart';

import '../byte_utils.dart';
import '../enums.dart';
import '../key/dsa_public_pgp_key.dart';
import '../key/ecdh_public_pgp_key.dart';
import '../key/ecdsa_public_pgp_key.dart';
import '../key/elgamal_public_pgp_key.dart';
import '../key/pgp_key.dart';
import '../key/rsa_public_pgp_key.dart';
import 'contained_packet.dart';

/// PublicKey represents an OpenPGP public key.
/// See RFC 4880, section 5.5.2.
class PublicKey extends ContainedPacket {
  static const tag = PacketTag.publicKey;

  final int version;

  final DateTime creationTime;

  final int expirationDays;

  final KeyAlgorithm algorithm;

  final PgpKey pgpKey;

  late final Uint8List _fingerprint;

  late final int _keyID;

  PublicKey(
    this.version,
    this.creationTime,
    this.pgpKey, {
    this.expirationDays = 0,
    this.algorithm = KeyAlgorithm.rsaEncryptSign,
  }) {
    _calculateFingerprintAndKeyID();
  }

  factory PublicKey.fromPacketData(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number (3, 4 or 5).
    final version = bytes[pos++];

    /// A four-octet number denoting the time that the key was created.
    final creationTime = ByteUtils.bytesToTime(bytes.sublist(pos, pos + 4));
    pos += 4;

    /// A two-octet number denoting the time in days that this key is valid.
    /// If this number is zero, then it does not expire.
    final expirationDays = (version == 3) ? ByteUtils.bytesToIn16(bytes.sublist(pos, pos + 2)) : 0;
    if (version == 3) {
      pos += 2;
    }

    // A one-octet number denoting the public-key algorithm of this key.
    final algorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos++]);
    if (version == 5) {
      /// - A four-octet scalar octet count for the following key material.
      pos += 4;
    }

    /// A series of values comprising the key material.
    /// This is algorithm-specific and described in section XXXX.
    final PgpKey key;
    switch (algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
        key = RsaPublicPgpKey.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.elgamal:
        key = ElGamalPublicPgpKey.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.dsa:
        key = DsaPublicPgpKey.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdh:
        key = ECDHPublicPgpKey.fromPacketData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdsa:
        key = ECDsaPublicPgpKey.fromPacketData(bytes.sublist(pos));
        break;
      default:
        throw UnsupportedError('Unknown PGP public key algorithm encountered');
    }
    return PublicKey(
      version,
      creationTime,
      key,
      expirationDays: expirationDays,
      algorithm: algorithm,
    );
  }

  /// Computes and set the fingerprint of the key
  void _calculateFingerprintAndKeyID() {
    final List<int> toHash = [];
    if (version <= 3) {
      final pk = pgpKey as RsaPublicPgpKey;
      final bytes = ByteUtils.bigIntBytes(pk.modulus);

      toHash.addAll(bytes);
      toHash.addAll(ByteUtils.bigIntBytes(pk.publicExponent));

      _fingerprint = Uint8List.fromList(md5.convert(toHash).bytes);
      _keyID = ByteUtils.bytesToInt64(bytes.sublist(bytes.length - 8));
    } else {
      final bytes = toPacketData();
      if (version == 5) {
        toHash.add(0x9A);
        toHash.addAll(ByteUtils.int32Bytes(bytes.length));
        toHash.addAll(bytes);

        _fingerprint = Uint8List.fromList(sha256.convert(toHash).bytes);
        _keyID = ByteUtils.bytesToInt64(_fingerprint.sublist(0, 8));
      } else if (version == 4) {
        toHash.add(0x99);
        toHash.addAll(ByteUtils.int16Bytes(bytes.length));
        toHash.addAll(bytes);

        _fingerprint = Uint8List.fromList(sha1.convert(toHash).bytes);
        _keyID = ByteUtils.bytesToInt64(_fingerprint.sublist(12, 20));
      } else {
        _fingerprint = Uint8List.fromList([]);
        _keyID = 0;
      }
    }
  }

  Uint8List get fingerprint => _fingerprint;

  int get keyID => _keyID;

  bool get isDecrypted => true;

  @override
  Uint8List toPacketData() {
    final List<int> bytes = [version & 0xff, ...ByteUtils.timeToBytes(creationTime)];
    if (version <= 3) {
      bytes.addAll(ByteUtils.int16Bytes(expirationDays));
    }
    bytes.add(algorithm.value & 0xff);

    final keyBytes = pgpKey.encode();
    if (version == 5) {
      bytes.addAll(ByteUtils.int32Bytes(keyBytes.length));
    }
    bytes.addAll(keyBytes);

    return Uint8List.fromList(bytes);
  }
}
