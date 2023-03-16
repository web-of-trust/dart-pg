// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../crypto/asymmetric/elgamal.dart';
import '../enum/key_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/symmetric_algorithm.dart';
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

  factory PublicKeyEncryptedSessionKeyPacket.fromByteData(final Uint8List bytes) {
    var pos = 0;
    final pkeskVersion = bytes[pos++];
    if (pkeskVersion != version) {
      throw UnsupportedError('Version $pkeskVersion of the PKESK packet is unsupported.');
    }

    final keyID = bytes.sublist(pos, pos + 8);
    pos += 8;

    final keyAlgorithm = KeyAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
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
        throw UnsupportedError('Unsupported PGP public key algorithm encountered');
    }

    return PublicKeyEncryptedSessionKeyPacket(
      KeyID(keyID),
      keyAlgorithm,
      params,
    );
  }

  factory PublicKeyEncryptedSessionKeyPacket.encryptSessionKey(
    final PublicKeyPacket publicKey, {
    final Uint8List? sessionKeyData,
    final SymmetricAlgorithm sessionKeySymmetric = SymmetricAlgorithm.aes256,
  }) {
    final sessionKey = SessionKey(
      sessionKeyData ?? Helper.generateEncryptionKey(sessionKeySymmetric),
      sessionKeySymmetric,
    );
    final SessionKeyParams params;
    switch (publicKey.algorithm) {
      case KeyAlgorithm.rsaEncryptSign:
      case KeyAlgorithm.rsaEncrypt:
        final rsaPublicKey = (publicKey.publicParams as RSAPublicParams).publicKey;
        params = RSASessionKeyParams.encryptSessionKey(rsaPublicKey, sessionKey);
        break;
      case KeyAlgorithm.elgamal:
        final elGamalPublicKey = (publicKey.publicParams as ElGamalPublicParams).publicKey;
        params = ElGamalSessionKeyParams.encryptSessionKey(elGamalPublicKey, sessionKey);
        break;
      case KeyAlgorithm.ecdh:
        params = ECDHSessionKeyParams.encryptSessionKey(
          (publicKey.publicParams as ECDHPublicParams),
          sessionKey,
          publicKey.fingerprint.hexToBytes(),
        );
        break;
      default:
        throw UnsupportedError('Unsupported PGP public key algorithm encountered');
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

  PublicKeyEncryptedSessionKeyPacket decrypt(final SecretKeyPacket key) {
    if (isDecrypted) {
      return this;
    } else {
      // check that session key algo matches the secret key algo and secret key is decrypted
      if (publicKeyAlgorithm != key.algorithm || !key.isDecrypted) {
        throw StateError('PKESK decryption error');
      }

      final SessionKey? sessionKey;
      switch (key.algorithm) {
        case KeyAlgorithm.rsaEncryptSign:
        case KeyAlgorithm.rsaEncrypt:
          final privateKey = (key.secretParams as RSASecretParams).privateKey;
          sessionKey = (sessionKeyParams as RSASessionKeyParams).decrypt(privateKey);
          break;
        case KeyAlgorithm.elgamal:
          final publicKey = (key.publicParams as ElGamalPublicParams).publicKey;
          final secretExponent = (key.secretParams as ElGamalSecretParams).secretExponent;
          sessionKey = (sessionKeyParams as ElGamalSessionKeyParams).decrypt(
            ElGamalPrivateKey(
              secretExponent,
              publicKey.prime,
              publicKey.generator,
            ),
          );
          break;
        case KeyAlgorithm.ecdh:
          final publicParams = key.publicParams as ECDHPublicParams;
          final privateKey = ECPrivateKey(
            (key.secretParams as ECSecretParams).d,
            publicParams.parameters,
          );
          sessionKey = (sessionKeyParams as ECDHSessionKeyParams).decrypt(
            privateKey,
            publicParams,
            key.fingerprint.hexToBytes(),
          );
          break;
        default:
          throw UnsupportedError('Unsupported PGP public key algorithm encountered');
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
