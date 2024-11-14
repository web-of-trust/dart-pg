// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../crypto/symmetric/base_cipher.dart';
import '../enum/aead_algorithm.dart';
import '../enum/hash_algorithm.dart';
import '../enum/packet_tag.dart';
import '../enum/s2k_type.dart';
import '../enum/symmetric_algorithm.dart';
import '../helpers.dart';
import 'key/s2k.dart';
import 'contained_packet.dart';
import 'key/session_key.dart';

/// SymEncryptedSessionKey represents a Symmetric-Key Encrypted Session Key packet.
///
/// See RFC 4880, section 5.3.
/// The Symmetric-Key Encrypted Session Key packet holds the
/// symmetric-key encryption of a session key used to encrypt a message.
/// Zero or more Public-Key Encrypted Session Key packets and/or
/// Symmetric-Key Encrypted Session Key packets may precede a
/// Symmetrically Encrypted Data packet that holds an encrypted message.
/// The message is encrypted with a session key, and the session key is
/// itself encrypted and stored in the Encrypted Session Key packet or
/// the Symmetric-Key Encrypted Session Key packet.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SymEncryptedSessionKeyPacket extends ContainedPacket {
  final int version;

  final SymmetricAlgorithm symmetric;

  final AeadAlgorithm aead;

  final S2K s2k;

  final Uint8List iv;

  final Uint8List encrypted;

  /// Session key
  final SessionKey? sessionKey;

  bool get isDecrypted => sessionKey != null;

  SymEncryptedSessionKeyPacket(
    this.version,
    this.s2k,
    this.iv,
    this.encrypted, {
    this.symmetric = SymmetricAlgorithm.aes128,
    this.aead = AeadAlgorithm.ocb,
    this.sessionKey,
  }) : super(PacketTag.symEncryptedSessionKey);

  factory SymEncryptedSessionKeyPacket.fromByteData(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number.
    final version = bytes[pos++];
    if (version != 4 && version != 5) {
      throw UnsupportedError(
        'Version $version of the SKESK packet is unsupported.',
      );
    }

    /// A one-octet number describing the symmetric algorithm used.
    final symmetric = SymmetricAlgorithm.values.firstWhere(
      (algo) => algo.value == bytes[pos],
    );
    pos++;

    final AeadAlgorithm aead;
    if (version == 5) {
      /// A one-octet number describing the aead algorithm used.
      aead = AeadAlgorithm.values.firstWhere(
        (algo) => algo.value == bytes[pos],
      );
      pos++;
    } else {
      aead = AeadAlgorithm.ocb;
    }

    /// A string-to-key (S2K) specifier, length as defined above.
    final s2k = S2K.fromByteData(bytes.sublist(pos));
    pos += s2k.length;

    final Uint8List iv;
    if (version == 5) {
      /// A starting initialization vector of size specified by the AEAD algorithm.
      iv = bytes.sublist(pos, pos + aead.ivLength);
      pos += aead.ivLength;
    } else {
      iv = Uint8List(0);
    }
    final encrypted = bytes.sublist(pos);

    return SymEncryptedSessionKeyPacket(
      version,
      s2k,
      iv,
      encrypted,
      symmetric: symmetric,
      aead: aead,
    );
  }

  static Future<SymEncryptedSessionKeyPacket> encryptSessionKey(
    final String password, {
    final SessionKey? sessionKey,
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    final AeadAlgorithm aead = AeadAlgorithm.ocb,
    final bool aeadProtect = false,
  }) async {
    final version = aeadProtect && sessionKey != null ? 5 : 4;
    final s2k = S2K(
      Helper.secureRandom().nextBytes(S2K.saltLength),
      hash: HashAlgorithm.sha256,
      type: S2kType.iterated,
    );

    final key = await s2k.produceKey(
      password,
      symmetric.keySizeInByte,
    );

    final Uint8List iv;
    final Uint8List encrypted;
    if (sessionKey != null) {
      if (version == 5) {
        final adata = Uint8List.fromList([
          0xC0 | PacketTag.symEncryptedSessionKey.value,
          version,
          symmetric.value,
          aead.value,
        ]);
        iv = Helper.secureRandom().nextBytes(aead.ivLength);
        final cipher = aead.cipherEngine(key, symmetric);
        encrypted = cipher.encrypt(sessionKey.key, iv, adata);
      } else {
        final cipher = BufferedCipher(
          symmetric.cfbCipherEngine,
        )..init(
            true,
            ParametersWithIV(
              KeyParameter(key),
              Uint8List(symmetric.blockSize),
            ),
          );
        iv = Uint8List(0);
        encrypted = cipher.process(sessionKey.encode());
      }
    } else {
      iv = Uint8List(0);
      encrypted = Uint8List(0);
    }

    return SymEncryptedSessionKeyPacket(
      version,
      s2k,
      iv,
      encrypted,
      symmetric: symmetric,
      aead: aead,
      sessionKey: sessionKey ?? SessionKey(key, symmetric),
    );
  }

  Future<SymEncryptedSessionKeyPacket> decrypt(final String password) async {
    if (isDecrypted) {
      return this;
    } else {
      final key = await s2k.produceKey(
        password,
        symmetric.keySizeInByte,
      );

      final SessionKey sessionKey;
      if (encrypted.isNotEmpty) {
        if (version == 5) {
          final adata = Uint8List.fromList([
            0xC0 | tag.value,
            version,
            symmetric.value,
            aead.value,
          ]);
          final cipher = aead.cipherEngine(key, symmetric);
          final decrypted = cipher.decrypt(encrypted, iv, adata);
          sessionKey = SessionKey(decrypted, symmetric);
        } else {
          final cipher = BufferedCipher(
            symmetric.cfbCipherEngine,
          )..init(
              false,
              ParametersWithIV(
                KeyParameter(key),
                Uint8List(symmetric.blockSize),
              ),
            );
          final decrypted = cipher.process(encrypted);
          final sessionKeySymmetric = SymmetricAlgorithm.values.firstWhere(
            (algo) => algo.value == decrypted[0],
          );
          sessionKey = SessionKey(decrypted.sublist(1), sessionKeySymmetric);
        }
      } else {
        sessionKey = SessionKey(key, symmetric);
      }

      return SymEncryptedSessionKeyPacket(
        version,
        s2k,
        iv,
        encrypted,
        symmetric: symmetric,
        sessionKey: sessionKey,
      );
    }
  }

  @override
  Uint8List toByteData() {
    return Uint8List.fromList([
      version,
      symmetric.value,
      ...s2k.encode(),
      ...encrypted,
    ]);
  }
}
