/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/helpers.dart';
import '../enum/eddsa_curve.dart';
import '../enum/hash_algorithm.dart';
import '../enum/key_version.dart';
import '../enum/montgomery_curve.dart';
import '../enum/key_algorithm.dart';
import '../enum/rsa_key_size.dart';
import '../type/key_material.dart';
import '../type/key_packet.dart';
import '../type/subkey_packet.dart';
import 'base.dart';
import 'key/public_material.dart';

/// Implementation of the Public Key (PUBKEY) Packet - Type 6
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PublicKeyPacket extends BasePacket implements KeyPacketInterface {
  static const keyIDSize = 8;

  @override
  final int keyVersion;

  @override
  final DateTime creationTime;

  @override
  final KeyAlgorithm keyAlgorithm;

  @override
  final KeyMaterialInterface keyMaterial;

  late final Uint8List _fingerprint;

  late final Uint8List _keyID;

  PublicKeyPacket(
    this.keyVersion,
    this.creationTime,
    this.keyMaterial, {
    this.keyAlgorithm = KeyAlgorithm.rsaEncryptSign,
  }) : super(PacketType.publicKey) {
    if (keyVersion != KeyVersion.v4.value && keyVersion != KeyVersion.v6.value) {
      throw UnsupportedError(
        'Version $keyVersion of the key packet is unsupported.',
      );
    }
    _assertKeyStrength();
    _calculateFingerprint();
  }

  factory PublicKeyPacket.fromBytes(final Uint8List bytes) {
    final keyRecord = parseBytes(bytes);
    return PublicKeyPacket(
      keyRecord.keyVersion,
      keyRecord.creationTime,
      keyRecord.keyMaterial,
      keyAlgorithm: keyRecord.keyAlgorithm,
    );
  }

  static ({
    int keyVersion,
    DateTime creationTime,
    KeyAlgorithm keyAlgorithm,
    KeyMaterialInterface keyMaterial,
  }) parseBytes(final Uint8List bytes) {
    var pos = 0;

    /// /// A one-octet version number (4 or 6).
    final version = bytes[pos++];

    /// A four-octet number denoting the time that the key was created.
    final creation = bytes.sublist(pos, pos + 4).toDateTime();
    pos += 4;

    /// A one-octet number denoting the public-key algorithm of this key.
    final algorithm = KeyAlgorithm.values.firstWhere(
      (algo) => algo.value == bytes[pos],
    );
    pos++;

    if (version == KeyVersion.v6.value) {
      /// A four-octet scalar octet count for the following key material.
      pos += 4;
    }
    return (
      keyVersion: version,
      creationTime: creation,
      keyAlgorithm: algorithm,
      keyMaterial: _readKeyMaterial(
        bytes.sublist(pos),
        algorithm,
      )
    );
  }

  @override
  get data {
    final kmBytes = keyMaterial.toBytes;
    return Uint8List.fromList([
      keyVersion,
      ...creationTime.toBytes(),
      keyAlgorithm.value,
      ...isV6Key ? kmBytes.length.pack32() : [],
      ...kmBytes,
    ]);
  }

  @override
  get fingerprint => _fingerprint;

  @override
  get isEncryptionKey => keyAlgorithm.forEncryption;

  @override
  get isSigningKey => keyAlgorithm.forSigning;

  @override
  get isSubkey => this is SubkeyPacketInterface;

  @override
  get keyID => _keyID;

  @override
  get keyStrength => keyMaterial.keyStrength;

  @override
  get signBytes => Uint8List.fromList([
        0x95 + keyVersion,
        ...isV6Key ? data.length.pack32() : data.length.pack16(),
        ...data,
      ]);

  bool get isV6Key => keyVersion == KeyVersion.v6.value;

  void _assertKeyStrength() {
    switch (keyAlgorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
      case KeyAlgorithm.rsaSign:
      case KeyAlgorithm.dsa:
      case KeyAlgorithm.elgamal:
        if (keyMaterial.keyStrength < RSAKeySize.normal.bits) {
          throw UnsupportedError(
            'Key strength ${keyMaterial.keyStrength} of the algorithm ${keyAlgorithm.name} is unsupported.',
          );
        }
      default:
    }
  }

  _calculateFingerprint() {
    if (isV6Key) {
      _fingerprint = Uint8List.fromList(
        Helper.hashDigest(signBytes, HashAlgorithm.sha256),
      );
      _keyID = _fingerprint.sublist(0, keyIDSize);
    } else {
      _fingerprint = Uint8List.fromList(
        Helper.hashDigest(signBytes, HashAlgorithm.sha1),
      );
      _keyID = _fingerprint.sublist(12, 12 + keyIDSize);
    }
  }

  static KeyMaterialInterface _readKeyMaterial(
    final Uint8List keyData,
    final KeyAlgorithm algorithm,
  ) {
    return switch (algorithm) {
      KeyAlgorithm.rsaEncryptSign ||
      KeyAlgorithm.rsaSign ||
      KeyAlgorithm.rsaEncrypt =>
        RSAPublicMaterial.fromBytes(keyData),
      KeyAlgorithm.dsa => DSAPublicMaterial.fromBytes(
          keyData,
        ),
      KeyAlgorithm.elgamal => ElGamalPublicMaterial.fromBytes(
          keyData,
        ),
      KeyAlgorithm.ecdsa => ECDSAPublicMaterial.fromBytes(
          keyData,
        ),
      KeyAlgorithm.ecdh => ECDHPublicMaterial.fromBytes(
          keyData,
        ),
      KeyAlgorithm.eddsaLegacy => EdDSALegacyPublicMaterial.fromBytes(
          keyData,
        ),
      KeyAlgorithm.x25519 => MontgomeryPublicMaterial.fromBytes(
          keyData,
          MontgomeryCurve.x25519,
        ),
      KeyAlgorithm.x448 => MontgomeryPublicMaterial.fromBytes(
          keyData,
          MontgomeryCurve.x448,
        ),
      KeyAlgorithm.ed25519 => EdDSAPublicMaterial.fromBytes(
          keyData,
          EdDSACurve.ed25519,
        ),
      KeyAlgorithm.ed448 => EdDSAPublicMaterial.fromBytes(
          keyData,
          EdDSACurve.ed448,
        ),
      _ => throw UnsupportedError(
          'Unsupported public key algorithm encountered',
        ),
    };
  }
}
