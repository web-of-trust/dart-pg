// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/asymmetric/elgamal.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../helpers.dart';
import 'contained_packet.dart';
import 'key/key_id.dart';
import 'key/key_params.dart';
import 'key/session_key.dart';
import 'key/session_key_params.dart';
import 'key_packet.dart';

/// PublicKeyEncryptedSessionKey represents a Public-Key Encrypted Session Key packet.
///
/// See RFC 4880, section 5.1.
/// A Public-Key Encrypted Session Key packet holds the session key used to encrypt a message.
/// Zero or more Public-Key Encrypted Session Key packets and/or Symmetric-Key Encrypted Session Key
/// packets may precede a Symmetrically Encrypted Data Packet, which holds an encrypted message.
/// The message is encrypted with the session key, and the session key is itself
/// encrypted and stored in the Encrypted Session Key packet(s).
/// The Symmetrically Encrypted Data Packet is preceded by one Public-Key Encrypted
/// Session Key packet for each OpenPGP key to which the message is encrypted.
/// The recipient of the message finds a session key that is encrypted to their public key,
/// decrypts the session key, and then uses the session key to decrypt the message.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PublicKeyEncryptedSessionKeyPacket extends ContainedPacket {
  static const version = 3;

  final KeyID publicKeyID;

  final KeyAlgorithm publicKeyAlgorithm;

  /// Encrypted session key params
  final SessionKeyParams sessionKeyParams;

  /// Session key
  final SessionKey? sessionKey;

  bool get isDecrypted => sessionKey != null;

  PublicKeyEncryptedSessionKeyPacket(
    this.publicKeyID,
    this.publicKeyAlgorithm,
    this.sessionKeyParams, {
    this.sessionKey,
  }) : super(PacketTag.publicKeyEncryptedSessionKey);

  factory PublicKeyEncryptedSessionKeyPacket.fromByteData(
      final Uint8List bytes) {
    var pos = 0;
    final pkeskVersion = bytes[pos++];
    if (pkeskVersion != version) {
      throw UnsupportedError(
        'Version $pkeskVersion of the PKESK packet is unsupported.',
      );
    }

    final keyID = bytes.sublist(pos, pos + 8);
    pos += 8;

    final keyAlgorithm =
        KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;

    final SessionKeyParams params;
    switch (keyAlgorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
        params = RSASessionKeyParams.fromByteData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.elgamal:
        params = ElGamalSessionKeyParams.fromByteData(bytes.sublist(pos));
        break;
      case KeyAlgorithm.ecdh:
        params = ECDHSessionKeyParams.fromByteData(bytes.sublist(pos));
        break;
      default:
        throw UnsupportedError(
          'Public key algorithm ${keyAlgorithm.name} of the PKESK packet is unsupported.',
        );
    }

    return PublicKeyEncryptedSessionKeyPacket(
      KeyID(keyID),
      keyAlgorithm,
      params,
    );
  }

  static Future<PublicKeyEncryptedSessionKeyPacket> encryptSessionKey(
    final PublicKeyPacket publicKey,
    final SessionKey sessionKey,
  ) async {
    final SessionKeyParams params;
    final keyParams = publicKey.publicParams;
    if (keyParams is RSAPublicParams) {
      params = await RSASessionKeyParams.encryptSessionKey(
        keyParams.publicKey,
        sessionKey,
      );
    } else if (keyParams is ElGamalPublicParams) {
      params = await ElGamalSessionKeyParams.encryptSessionKey(
        keyParams.publicKey,
        sessionKey,
      );
    } else if (keyParams is ECDHPublicParams) {
      params = await ECDHSessionKeyParams.encryptSessionKey(
        keyParams,
        sessionKey,
        publicKey.fingerprint.hexToBytes(),
      );
    } else {
      throw UnsupportedError(
        'Public key algorithm ${publicKey.algorithm.name} is unsupported for session key encryption.',
      );
    }
    return PublicKeyEncryptedSessionKeyPacket(
      publicKey.keyID,
      publicKey.algorithm,
      params,
      sessionKey: sessionKey,
    );
  }

  @override
  Uint8List toByteData() {
    return Uint8List.fromList([
      version,
      ...publicKeyID.bytes,
      publicKeyAlgorithm.value,
      ...sessionKeyParams.encode(),
    ]);
  }

  Future<PublicKeyEncryptedSessionKeyPacket> decrypt(
      final SecretKeyPacket key) async {
    if (isDecrypted) {
      return this;
    } else {
      // check that session key algo matches the secret key algo and secret key is decrypted
      if (publicKeyAlgorithm != key.algorithm || !key.isDecrypted) {
        throw ArgumentError(
          'Secret key packet is invalid for session key decryption',
        );
      }

      final SessionKey? sessionKey;
      final keyParams = sessionKeyParams;
      if (keyParams is RSASessionKeyParams) {
        final privateKey = (key.secretParams as RSASecretParams).privateKey;
        sessionKey = await keyParams.decrypt(privateKey);
      } else if (keyParams is ElGamalSessionKeyParams) {
        final publicKey = (key.publicParams as ElGamalPublicParams).publicKey;
        sessionKey = await keyParams.decrypt(
          ElGamalPrivateKey(
            (key.secretParams as ElGamalSecretParams).exponent,
            publicKey.prime,
            publicKey.generator,
          ),
        );
      } else if (keyParams is ECDHSessionKeyParams) {
        sessionKey = await keyParams.decrypt(
          key.secretParams as ECSecretParams,
          key.publicParams as ECDHPublicParams,
          key.fingerprint.hexToBytes(),
        );
      } else {
        throw UnsupportedError(
          'Public key algorithm ${key.algorithm.name} is unsupported for session key decryption.',
        );
      }

      return PublicKeyEncryptedSessionKeyPacket(
        publicKeyID,
        publicKeyAlgorithm,
        sessionKeyParams,
        sessionKey: sessionKey,
      );
    }
  }
}
