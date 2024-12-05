/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../enum/hash_algorithm.dart';
import '../enum/symmetric_algorithm.dart';
import '../enum/aead_algorithm.dart';
import 'key_packet.dart';
import 'secret_key_material.dart';

/// Secret key packet interface
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract interface class SecretKeyPacketInterface implements KeyPacketInterface {
  /// Get public key packet
  KeyPacketInterface get publicKey;

  /// Get secret key material
  SecretKeyMaterialInterface? get secretKeyMaterial;

  /// Secret key packet is encrypted
  bool get isEncrypted;

  /// Secret key packet is decrypted
  bool get isDecrypted;

  /// Secret key packet is aead protected
  bool get aeadProtected;

  /// Get preferred hash algorithm
  HashAlgorithm get preferredHash;

  /// Encrypt secret key packet with passphrase
  SecretKeyPacketInterface encrypt(
    final String passphrase,
    final SymmetricAlgorithm symmetric, [
    final AeadAlgorithm? aead,
  ]);

  /// Decrypt secret key packet with passphrase
  SecretKeyPacketInterface decrypt(final String passphrase);
}
