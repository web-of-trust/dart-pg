/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:sign_dart/sign_dart.dart';

import '../../common/helpers.dart';
import '../../enum/eddsa_curve.dart';
import '../../enum/hash_algorithm.dart';
import '../../type/signing_key_material.dart';
import 'eddsa_public_material.dart';

/// EdDSA secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class EdDSASecretMaterial implements SigningKeyMaterialInterface {
  final Uint8List secretKey;

  @override
  final EdDSAPublicMaterial publicMaterial;

  EdDSASecretMaterial(this.secretKey, this.publicMaterial);

  factory EdDSASecretMaterial.fromBytes(
    final Uint8List bytes,
    final EdDSAPublicMaterial publicMaterial,
  ) =>
      EdDSASecretMaterial(
        bytes.sublist(
          0,
          publicMaterial.curve.payloadSize,
        ),
        publicMaterial,
      );

  factory EdDSASecretMaterial.generate(final EdDSACurve curve) {
    final secretKey = Helper.secureRandom().nextBytes(curve.payloadSize);
    final publicKey = switch (curve) {
      EdDSACurve.ed25519 => nacl.PrivateKey(
          secretKey,
        ).publicKey.asTypedList,
      EdDSACurve.ed448 => EdPrivateKey.fromBytes(
          secretKey,
          TwistedEdwardCurve.ed448(),
        ).getPublicKey().publicKey,
    };
    return EdDSASecretMaterial(
      secretKey,
      EdDSAPublicMaterial(
        publicKey,
        curve,
      ),
    );
  }

  @override
  bool get isValid {
    final publicKey = switch (publicMaterial.curve) {
      EdDSACurve.ed25519 => nacl.PrivateKey(
          secretKey,
        ).publicKey.asTypedList,
      EdDSACurve.ed448 => EdPrivateKey.fromBytes(
          secretKey,
          TwistedEdwardCurve.ed448(),
        ).getPublicKey().publicKey,
    };
    return publicMaterial.publicKey.equals(publicKey);
  }

  @override
  int get keyStrength => publicMaterial.keyStrength;

  @override
  Uint8List sign(
    final Uint8List message,
    final HashAlgorithm hash,
  ) =>
      switch (publicMaterial.curve) {
        EdDSACurve.ed25519 => nacl.SigningKey.fromValidBytes(
            Uint8List.fromList([
              ...secretKey,
              ...publicMaterial.publicKey,
            ]),
          )
              .sign(
                Helper.hashDigest(message, hash),
              )
              .asTypedList,
        EdDSACurve.ed448 => EdPrivateKey.fromBytes(
            secretKey,
            TwistedEdwardCurve.ed448(),
          ).sign(
            Helper.hashDigest(message, hash),
          ),
      };

  @override
  Uint8List get toBytes => secretKey;
}
