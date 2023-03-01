// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../crypto/symmetric/base_cipher.dart';
import '../enums.dart';
import '../helpers.dart';
import '../openpgp.dart';
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
class SymEncryptedSessionKeyPacket extends ContainedPacket {
  static const version = OpenPGP.skeskVersion;

  /// Algorithm to encrypt the session key with
  final SymmetricAlgorithm symmetric;

  final S2K s2k;

  final Uint8List encrypted;

  /// Session key
  final SessionKey? sessionKey;

  bool get isDecrypted => sessionKey != null;

  SymEncryptedSessionKeyPacket(
    this.s2k,
    this.encrypted, {
    this.symmetric = OpenPGP.preferredSymmetric,
    this.sessionKey,
  }) : super(PacketTag.symEncryptedSessionKey);

  factory SymEncryptedSessionKeyPacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;

    /// A one-octet version number. The only currently defined version is 4.
    final version = bytes[pos++];
    if (version != OpenPGP.skeskVersion) {
      throw UnsupportedError('Version $version of the SKESK packet is unsupported.');
    }

    /// A one-octet number describing the symmetric algorithm used.
    final symmetric = SymmetricAlgorithm.values.firstWhere((algo) => algo.value == bytes[pos]);
    pos++;

    /// A string-to-key (S2K) specifier, length as defined above.
    final s2k = S2K.fromPacketData(bytes.sublist(pos));

    return SymEncryptedSessionKeyPacket(
      s2k,
      bytes.sublist(pos + s2k.length),
      symmetric: symmetric,
    );
  }

  factory SymEncryptedSessionKeyPacket.encryptSessionKey(
    final String password, {
    final Uint8List? sessionKeyData,
    final SymmetricAlgorithm sessionKeySymmetric = OpenPGP.preferredSymmetric,
    final SymmetricAlgorithm symmetric = OpenPGP.preferredSymmetric,
    final HashAlgorithm hash = OpenPGP.preferredHash,
    final S2kType type = S2kType.iterated,
  }) {
    final s2k = S2K(Helper.secureRandom().nextBytes(8), hash: hash, type: type);
    final key = s2k.produceKey(password, symmetric);
    final cipher = BufferedCipher(symmetric.cipherEngine)..init(true, KeyParameter(key));
    final sessionKey = SessionKey(
      sessionKeyData ?? Helper.generateEncryptionKey(sessionKeySymmetric),
      sessionKeySymmetric,
    );

    return SymEncryptedSessionKeyPacket(
      s2k,
      cipher.process(sessionKey.encode()),
      symmetric: symmetric,
      sessionKey: sessionKey,
    );
  }

  SymEncryptedSessionKeyPacket decrypt(final String passphrase) {
    if (isDecrypted) {
      return this;
    } else {
      final key = s2k.produceKey(passphrase, symmetric);
      final cipher = BufferedCipher(symmetric.cipherEngine)..init(false, KeyParameter(key));
      final decrypted = cipher.process(encrypted);
      final sessionKeySymmetric = SymmetricAlgorithm.values.firstWhere((algo) => algo.value == decrypted[0]);
      return SymEncryptedSessionKeyPacket(
        s2k,
        encrypted,
        symmetric: symmetric,
        sessionKey: SessionKey(decrypted.sublist(1), sessionKeySymmetric),
      );
    }
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      version,
      symmetric.value,
      ...s2k.encode(),
      ...encrypted,
    ]);
  }
}
