/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../common/argon2_s2k.dart';
import '../common/generic_s2k.dart';
import '../common/helpers.dart';
import '../cryptor/symmetric/buffered_cipher.dart';
import '../enum/aead_algorithm.dart';
import '../enum/s2k_type.dart';
import '../enum/symmetric_algorithm.dart';
import '../type/s2k.dart';
import '../type/session_key.dart';
import 'base.dart';
import 'key/session_key.dart';

/// Implementation of the Symmetric Key Encrypted Session Key (SKESK) Packet - Type 3
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SymEncryptedSessionKeyPacket extends BasePacket {
  final int version;

  final SymmetricAlgorithm symmetric;

  final AeadAlgorithm? aead;

  final S2kInterface s2k;

  final Uint8List iv;

  final Uint8List encrypted;

  final SessionKeyInterface? sessionKey;

  bool get isDecrypted => sessionKey != null;

  SymEncryptedSessionKeyPacket(
    this.version,
    this.s2k,
    this.iv,
    this.encrypted, {
    this.symmetric = SymmetricAlgorithm.aes128,
    this.aead,
    this.sessionKey,
  }) : super(PacketType.symEncryptedSessionKey) {
    if (version != 4 && version != 5 && version != 6) {
      throw UnsupportedError(
        'Version $version of the SKESK packet is unsupported.',
      );
    }
    if (version == 6) {
      Helper.assertSymmetric(symmetric);
    }
    if (aead != null && version < 5) {
      throw ArgumentError(
        'Using AEAD with version $version SKESK packet is not allowed.',
      );
    }
  }

  factory SymEncryptedSessionKeyPacket.fromBytes(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number.
    final version = bytes[pos++];
    final isV6 = version == 6;

    if (isV6) {
      /// A one-octet scalar octet count of the following 5 fields.
      pos++;
    }

    /// A one-octet number describing the symmetric algorithm used.
    final symmetric = SymmetricAlgorithm.values.firstWhere(
      (algo) => algo.value == bytes[pos],
    );
    pos++;

    final int ivLength;
    final AeadAlgorithm? aead;
    if (version >= 5) {
      /// A one-octet number describing the aead algorithm used.
      aead = AeadAlgorithm.values.firstWhere(
        (algo) => algo.value == bytes[pos],
      );
      ivLength = aead.ivLength;
      pos++;
      if (isV6) {
        // A one-octet scalar octet count of the following field.
        pos++;
      }
    } else {
      ivLength = 0;
      aead = null;
    }

    /// A string-to-key (S2K) specifier, length as defined above.
    final s2kType = S2kType.values.firstWhere(
      (type) => type.value == bytes[pos],
    );
    final s2k = switch (s2kType) {
      S2kType.argon2 => Argon2S2k.fromBytes(bytes.sublist(pos)),
      _ => GenericS2k.fromBytes(bytes.sublist(pos)),
    };
    pos += s2k.length;

    /// A starting initialization vector of size specified by the AEAD algorithm.
    final iv = bytes.sublist(pos, pos + ivLength);
    pos += ivLength;

    return SymEncryptedSessionKeyPacket(
      version,
      s2k,
      iv,
      bytes.sublist(pos),
      symmetric: symmetric,
      aead: aead,
    );
  }

  factory SymEncryptedSessionKeyPacket.encryptSessionKey(
    final String password, {
    final SessionKeyInterface? sessionKey,
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
    final AeadAlgorithm aead = AeadAlgorithm.gcm,
    final bool aeadProtect = false,
  }) {
    final version = aeadProtect && sessionKey != null ? 6 : 4;
    final s2k = aeadProtect
        ? Helper.stringToKey(
            S2kType.argon2,
          )
        : Helper.stringToKey(
            S2kType.iterated,
          );

    final key = s2k.produceKey(
      password,
      symmetric.keySizeInByte,
    );

    final Uint8List iv;
    final Uint8List encrypted;
    if (sessionKey != null) {
      if (aeadProtect) {
        final adata = Uint8List.fromList([
          0xc0 | PacketType.symEncryptedSessionKey.value,
          version,
          symmetric.value,
          aead.value,
        ]);

        final kek = Helper.hkdf(key, symmetric.keySizeInByte, info: adata);

        iv = Helper.randomBytes(aead.ivLength);
        final cipher = aead.cipherEngine(kek, symmetric);
        encrypted = cipher.encrypt(sessionKey.encryptionKey, iv, adata);
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
      aead: aeadProtect ? aead : null,
      sessionKey: sessionKey ?? SessionKey(key, symmetric),
    );
  }

  SymEncryptedSessionKeyPacket decrypt(final String password) {
    if (isDecrypted) {
      return this;
    } else {
      final key = s2k.produceKey(
        password,
        symmetric.keySizeInByte,
      );

      final SessionKey sessionKey;
      if (encrypted.isNotEmpty) {
        if (aead != null) {
          final adata = Uint8List.fromList([
            0xC0 | type.value,
            version,
            symmetric.value,
            aead!.value,
          ]);

          final Uint8List kek = version == 6
              ? Helper.hkdf(
                  key,
                  symmetric.keySizeInByte,
                  info: adata,
                )
              : key;

          final cipher = aead!.cipherEngine(kek, symmetric);
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
  Uint8List get data => Uint8List.fromList([
        version,
        ...version == 6 ? [3 + s2k.length + iv.length] : [],
        symmetric.value,
        ...aead != null ? [aead!.value] : [],
        ...version == 6 ? [s2k.length] : [],
        ...s2k.toBytes,
        ...iv,
        ...encrypted,
      ]);
}
