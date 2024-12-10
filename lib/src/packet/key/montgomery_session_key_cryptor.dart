/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../common/helpers.dart';
import '../../enum/montgomery_curve.dart';
import '../../type/secret_key_material.dart';
import 'key_wrapper.dart';
import 'montgomery_public_material.dart';
import 'montgomery_secret_material.dart';
import 'session_key_cryptor.dart';

class MontgomerySessionKeyCryptor extends SessionKeyCryptor {
  /// The ephemeral key used to establish the shared secret
  final Uint8List ephemeralKey;

  /// ECDH wrapped key
  final Uint8List wrappedKey;

  MontgomerySessionKeyCryptor(this.ephemeralKey, this.wrappedKey);

  factory MontgomerySessionKeyCryptor.fromBytes(
    final Uint8List bytes,
    final MontgomeryCurve curve,
  ) {
    return MontgomerySessionKeyCryptor(
      bytes.sublist(0, curve.payloadSize),
      bytes.sublist(
        curve.payloadSize + 1,
        curve.payloadSize + 1 + bytes[curve.payloadSize],
      ),
    );
  }

  factory MontgomerySessionKeyCryptor.encryptSessionKey(
    final Uint8List sessionKey,
    final MontgomeryPublicMaterial key,
  ) {
    final secretKey = MontgomerySecretMaterial.generate(key.curve);
    final ephemeralKey = secretKey.publicMaterial.publicKey;
    final keyWrapper = AesKeyWrapper(key.curve.kekSize);
    return MontgomerySessionKeyCryptor(
      ephemeralKey,
      keyWrapper.wrap(
        Helper.hkdf(
          Uint8List.fromList([
            ...ephemeralKey,
            ...key.publicKey,
            ...secretKey.computeSecret(key.publicKey),
          ]),
          key.curve.kekSize,
          info: key.curve.hkdfInfo,
          hash: key.curve.hkdfHash,
        ),
        sessionKey,
      ),
    );
  }

  @override
  decrypt(final SecretKeyMaterialInterface key) {
    if (key is MontgomerySecretMaterial) {
      final keyWrapper = AesKeyWrapper(
        key.publicMaterial.curve.kekSize,
      );
      return keyWrapper.unwrap(
        Helper.hkdf(
          Uint8List.fromList([
            ...ephemeralKey,
            ...key.publicMaterial.publicKey,
            ...key.computeSecret(ephemeralKey),
          ]),
          key.publicMaterial.curve.kekSize,
          info: key.publicMaterial.curve.hkdfInfo,
          hash: key.publicMaterial.curve.hkdfHash,
        ),
        wrappedKey,
      );
    } else {
      throw ArgumentError('Secret key material is not Montgomery key.');
    }
  }

  @override
  toBytes() => Uint8List.fromList([
        ...ephemeralKey,
        wrappedKey.length,
        ...wrappedKey,
      ]);
}
