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
import '../../type/verification_key_material.dart';

/// EdDSA public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class EdDSAPublicMaterial implements VerificationKeyMaterial {
  final Uint8List publicKey;

  final EdDSACurve curve;

  EdDSAPublicMaterial(this.publicKey, this.curve);

  factory EdDSAPublicMaterial.fromBytes(
    final Uint8List bytes,
    final EdDSACurve curve,
  ) =>
      EdDSAPublicMaterial(
        bytes.sublist(
          0,
          curve.payloadSize,
        ),
        curve,
      );

  @override
  int get keyLength => publicKey.toBigInt().bitLength;

  @override
  Uint8List get toBytes => publicKey;

  @override
  bool verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) =>
      switch (curve) {
        EdDSACurve.ed25519 => nacl.VerifyKey(publicKey).verify(
            signature: nacl.Signature(signature),
            message: Helper.hashDigest(message, hash),
          ),
        EdDSACurve.ed448 => EdPublicKey.fromBytes(
            publicKey,
            TwistedEdwardCurve.ed448(),
          ).verify(
            Helper.hashDigest(message, hash),
            signature,
          ),
      };
}
