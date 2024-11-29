/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:pinenacl/tweetnacl.dart';

import '../../common/helpers.dart';
import '../../type/secret_key_material.dart';
import '../../cryptor/dh/x448.dart';
import '../../enum/montgomery_curve.dart';
import 'montgomery_public_material.dart';

/// Montgomery secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class MontgomerySecretMaterial implements SecretKeyMaterialInterface {
  final Uint8List secretKey;

  @override
  final MontgomeryPublicMaterial publicMaterial;

  MontgomerySecretMaterial(this.secretKey, this.publicMaterial);

  factory MontgomerySecretMaterial.fromBytes(
    final Uint8List bytes,
    final MontgomeryPublicMaterial publicMaterial,
  ) =>
      MontgomerySecretMaterial(
        bytes.sublist(0, publicMaterial.curve.payloadSize),
        publicMaterial,
      );

  factory MontgomerySecretMaterial.generate(final MontgomeryCurve curve) {
    final secretKey = _generateSecretKey(curve);
    final publicKey = switch (curve) {
      MontgomeryCurve.x25519 => nacl.PrivateKey(
          secretKey,
        ).publicKey.asTypedList,
      MontgomeryCurve.x448 => X448.scalarMultBase(secretKey),
    };
    return MontgomerySecretMaterial(
      secretKey,
      MontgomeryPublicMaterial(
        publicKey,
        curve,
      ),
    );
  }

  @override
  int get keyStrength => publicMaterial.keyStrength;

  @override
  Uint8List get toBytes => secretKey;

  @override
  bool get isValid {
    final publicKey = switch (publicMaterial.curve) {
      MontgomeryCurve.x25519 => nacl.PrivateKey(
          secretKey,
        ).publicKey.asTypedList,
      MontgomeryCurve.x448 => X448.scalarMultBase(secretKey),
    };
    return publicMaterial.publicKey.equals(publicKey);
  }

  /// Compute shared secret
  Uint8List computeSecret(final Uint8List publicKey) {
    assert(publicKey.length == publicMaterial.curve.payloadSize);
    return switch (publicMaterial.curve) {
      MontgomeryCurve.x25519 => TweetNaCl.crypto_scalarmult(
          Uint8List(publicMaterial.curve.payloadSize),
          secretKey,
          publicKey,
        ),
      MontgomeryCurve.x448 => X448.scalarMult(secretKey, publicKey),
    };
  }

  static Uint8List _generateSecretKey(final MontgomeryCurve curve) {
    final payloadSize = curve.payloadSize;
    final key = Helper.randomBytes(payloadSize);
    switch (curve) {
      case MontgomeryCurve.x25519:
        // The lowest three bits must be 0
        key[0] &= 0xf8;
        // The highest bit must be 0 & the second highest bit must be 1
        key[payloadSize - 1] = (key[payloadSize - 1] & 0x7f) | 0x40;
      case MontgomeryCurve.x448:
        // The two least significant bits of the first byte to 0
        key[0] &= 0xfc;
        // The most significant bit of the last byte to 1
        key[payloadSize - 1] |= 0x80;
    }
    return key;
  }
}
