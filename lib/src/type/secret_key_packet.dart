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
abstract class SecretKeyPacketInterface extends KeyPacketInterface {
  /// Get public key packet
  KeyPacketInterface get publicKey;

  /// Get secret key material
  SecretKeyMaterialInterface? get secretKeyMaterial;

  /// Get aead algorithm
  AeadAlgorithm? get aead;

  /// Secret key packed is encrypted
  bool get isEncrypted;

  /// Secret key packed is decrypted
  bool get isDecrypted;

  /// Get preferred hash algorithm
  HashAlgorithm get preferredHash;

  SecretKeyPacketInterface encrypt(
    String passphrase,
    SymmetricAlgorithm symmetric,
    AeadAlgorithm? aead,
  );

  SecretKeyPacketInterface decrypt(String passphrase);
}
