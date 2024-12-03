/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../enum/hash_algorithm.dart';
import 'key.dart';
import 'secret_key_packet.dart';

/// OpenPGP private key interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class PrivateKeyInterface implements KeyInterface {
  /// Get secret key packet
  SecretKeyPacketInterface get secretKeyPacket;

  /// Private key is encrypted
  bool get isEncrypted;

  /// Private key is decrypted
  bool get isDecrypted;

  /// Private key is aead protected
  bool get aeadProtected;

  /// Get preferred hash algorithm
  HashAlgorithm get preferredHash;

  /// Lock a private key with the given passphrase.
  /// This method does not change the original key.
  PrivateKeyInterface encrypt(
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]);

  /// Unlock a private key with the given passphrase.
  /// This method does not change the original key.
  PrivateKeyInterface decrypt(
    final String passphrase, [
    final Iterable<String> subkeyPassphrases = const [],
  ]);
}
