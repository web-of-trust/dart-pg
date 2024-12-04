/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import '../../common/helpers.dart';
import '../../type/secret_key_material.dart';
import 'rsa_public_material.dart';
import 'rsa_secret_material.dart';
import 'session_key_cryptor.dart';

/// RSA session key cryptor class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class RSASessionKeyCryptor extends SessionKeyCryptor {
  /// multiprecision integer (MPI) of RSA encrypted value m**e mod n.
  final BigInt encrypted;

  RSASessionKeyCryptor(this.encrypted);

  factory RSASessionKeyCryptor.fromBytes(
    final Uint8List bytes,
  ) =>
      RSASessionKeyCryptor(Helper.readMPI(bytes));

  factory RSASessionKeyCryptor.encryptSessionKey(
    final Uint8List sessionKey,
    final RSAPublicMaterial key,
  ) {
    return RSASessionKeyCryptor(
      SessionKeyCryptor.processInBlocks(
        AsymmetricBlockCipher('RSA/PKCS1')
          ..init(
            true,
            PublicKeyParameter<RSAPublicKey>(key.publicKey),
          ),
        sessionKey,
      ).toUnsignedBigInt(),
    );
  }

  @override
  decrypt(final SecretKeyMaterialInterface key) {
    if (key is RSASecretMaterial) {
      return SessionKeyCryptor.processInBlocks(
        AsymmetricBlockCipher('RSA/PKCS1')
          ..init(
            false,
            PrivateKeyParameter<RSAPrivateKey>(key.privateKey),
          ),
        encrypted.toUnsignedBytes(),
      );
    } else {
      throw ArgumentError('Secret key material is not RSA key.');
    }
  }

  @override
  toBytes() => Uint8List.fromList([
        ...encrypted.bitLength.pack16(),
        ...encrypted.toUnsignedBytes(),
      ]);
}
