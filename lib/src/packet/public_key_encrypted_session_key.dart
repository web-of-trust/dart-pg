/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../type/key_packet.dart';
import '../enum/key_algorithm.dart';
import '../enum/montgomery_curve.dart';
import '../type/session_key.dart';
import '../type/session_key_cryptor.dart';
import 'base_packet.dart';
import 'key/public_material.dart';
import 'key/session_key_cryptor.dart';

/// Implementation of the Public-Key Encrypted Session Key (PKESK) Packet - Type 1
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PublicKeyEncryptedSessionKeyPacket extends BasePacket {
  final int version;

  final int keyVersion;

  final Uint8List keyFingerprint;

  final Uint8List keyID;

  final KeyAlgorithm keyAlgorithm;

  final SessionKeyCryptorInterface cryptor;

  final SessionKeyInterface? sessionKey;

  PublicKeyEncryptedSessionKeyPacket(
    this.version,
    this.keyVersion,
    this.keyFingerprint,
    this.keyID,
    this.keyAlgorithm,
    this.cryptor, {
    this.sessionKey,
  }) : super(PacketType.publicKeyEncryptedSessionKey) {
    if (version != 3 && version != 6) {
      throw UnsupportedError(
        'Version $version of the PKESK packet is unsupported.',
      );
    }
    if (version == 6 && keyAlgorithm == KeyAlgorithm.elgamal) {
      throw ArgumentError(
        'Key algorithm ${keyAlgorithm.name} '
        'cannot be used with version {$version} PKESK packet.',
      );
    }
  }

  factory PublicKeyEncryptedSessionKeyPacket.fromBytes(
    final Uint8List bytes,
  ) {
    var pos = 0;
    final version = bytes[pos++];

    final int keyVersion;
    final Uint8List keyFingerprint;
    final Uint8List keyID;
    if (version == 6) {
      final length = bytes[pos++];
      keyVersion = bytes[pos++];
      keyFingerprint = bytes.sublist(pos, pos + length - 1);
      pos += length - 1;
      keyID = keyVersion == 6
          ? keyFingerprint.sublist(0, PublicKeyPacket.keyIDSize)
          : keyFingerprint.sublist(12, 12 + PublicKeyPacket.keyIDSize);
    } else {
      keyVersion = 0;
      keyFingerprint = Uint8List(0);
      keyID = bytes.sublist(pos, pos + PublicKeyPacket.keyIDSize);
      pos += PublicKeyPacket.keyIDSize;
    }
    final keyAlgorithm = KeyAlgorithm.values.firstWhere(
      (algo) => algo.value == bytes[pos],
    );
    pos++;

    final sessionKeyCryptor = switch (keyAlgorithm) {
      KeyAlgorithm.rsaEncryptSign ||
      KeyAlgorithm.rsaEncrypt =>
        RSASessionKeyCryptor.fromBytes(
          bytes.sublist(pos),
        ),
      KeyAlgorithm.elgamal => ElGamalSessionKeyCryptor.fromBytes(
          bytes.sublist(pos),
        ),
      KeyAlgorithm.ecdh => ECDHSessionKeyCryptor.fromBytes(
          bytes.sublist(pos),
        ),
      KeyAlgorithm.x25519 => MontgomerySessionKeyCryptor.fromBytes(
          bytes.sublist(pos),
          MontgomeryCurve.x25519,
        ),
      KeyAlgorithm.x448 => MontgomerySessionKeyCryptor.fromBytes(
          bytes.sublist(pos),
          MontgomeryCurve.x448,
        ),
      _ => throw UnsupportedError(
          'Key algorithm ${keyAlgorithm.name} '
          'of the PKESK packet is unsupported.',
        )
    };

    return PublicKeyEncryptedSessionKeyPacket(
      version,
      keyVersion,
      keyFingerprint,
      keyID,
      keyAlgorithm,
      sessionKeyCryptor,
    );
  }

  factory PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
    KeyPacketInterface keyPacket,
    SessionKeyInterface sessionKey,
  ) {
    final version = keyPacket.keyVersion == 6 ? 6 : 3;
    final keyData = switch (keyPacket.keyAlgorithm) {
      KeyAlgorithm.x25519 || KeyAlgorithm.x448 => sessionKey.encryptionKey,
      _ => version == 3
          ? Uint8List.fromList([
              ...sessionKey.toBytes(),
              ...sessionKey.computeChecksum(),
            ])
          : Uint8List.fromList([
              ...sessionKey.encryptionKey,
              ...sessionKey.computeChecksum(),
            ]),
    };

    final cryptor = switch (keyPacket.keyAlgorithm) {
      KeyAlgorithm.rsaEncryptSign ||
      KeyAlgorithm.rsaEncrypt =>
        RSASessionKeyCryptor.encryptSessionKey(
          keyData,
          keyPacket.keyMaterial as RSAPublicMaterial,
        ),
      KeyAlgorithm.ecdh => ECDHSessionKeyCryptor.encryptSessionKey(
          keyData,
          keyPacket.keyMaterial as ECDHPublicMaterial,
          keyPacket.fingerprint,
        ),
      KeyAlgorithm.x25519 ||
      KeyAlgorithm.x448 =>
        MontgomerySessionKeyCryptor.encryptSessionKey(
          keyData,
          keyPacket.keyMaterial as MontgomeryPublicMaterial,
        ),
      _ => throw UnsupportedError(
          'Key algorithm ${keyPacket.keyAlgorithm.name} '
          'is unsupported for session key encryption.',
        ),
    };
    return PublicKeyEncryptedSessionKeyPacket(
      version,
      keyPacket.keyVersion,
      keyPacket.fingerprint,
      keyPacket.keyID,
      keyPacket.keyAlgorithm,
      cryptor,
    );
  }

  @override
  get data => Uint8List.fromList([
        version,
        ...version == 6 ? [keyFingerprint.length + 1] : [],
        ...version == 6 ? [keyVersion] : [],
        ...version == 6 ? keyFingerprint : [],
        ...version == 3 ? keyID : [],
        keyAlgorithm.value,
        ...cryptor.toBytes(),
      ]);

  PublicKeyEncryptedSessionKeyPacket decrypt(
    final SecretKeyPacketInterface key,
  ) {
    if (sessionKey != null) {
      return this;
    } else {
      if (keyAlgorithm != key.keyAlgorithm || !key.isDecrypted) {
        throw ArgumentError(
          'Secret key packet is invalid for session key decryption',
        );
      }
      if (cryptor is ECDHSessionKeyCryptor) {
        (cryptor as ECDHSessionKeyCryptor).fingerprint = key.fingerprint;
      }
      final keyData = cryptor.decrypt(key.secretKeyMaterial!);
      final SessionKeyInterface sessionKey;
      if (version == 3) {
        sessionKey = SessionKey.fromBytes(keyData);
      } else {
        switch (keyAlgorithm) {
          case KeyAlgorithm.x25519:
            sessionKey = SessionKey(
              keyData,
              MontgomeryCurve.x25519.symmetric,
            );
            break;
          case KeyAlgorithm.x448:
            sessionKey = SessionKey(
              keyData,
              MontgomeryCurve.x448.symmetric,
            );
            break;
          default:
            final keyLength = keyData.length - 2;
            sessionKey = SessionKey(keyData.sublist(0, keyLength));
            sessionKey.checksum(keyData.sublist(keyLength));
        }
      }

      return PublicKeyEncryptedSessionKeyPacket(
        version,
        keyVersion,
        keyFingerprint,
        keyID,
        keyAlgorithm,
        cryptor,
        sessionKey: sessionKey,
      );
    }
  }
}
