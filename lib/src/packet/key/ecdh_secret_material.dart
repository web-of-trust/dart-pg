/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pinenacl/ed25519.dart' as nacl;
import 'package:pinenacl/tweetnacl.dart';
import 'package:pointycastle/pointycastle.dart';

import '../../common/helpers.dart';
import '../../enum/ecc.dart';
import '../../type/secret_key_material.dart';
import 'ec_secret_material.dart';
import 'ecdh_public_material.dart';

/// ECDH secret key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ECDHSecretMaterial extends ECSecretMaterial implements SecretKeyMaterialInterface {
  @override
  final ECDHPublicMaterial publicMaterial;

  ECDHSecretMaterial(super.d, this.publicMaterial);

  factory ECDHSecretMaterial.fromBytes(
    final Uint8List bytes,
    final ECDHPublicMaterial publicMaterial,
  ) =>
      ECDHSecretMaterial(
        Helper.readMPI(bytes),
        publicMaterial,
      );

  factory ECDHSecretMaterial.generate(Ecc curve) {
    switch (curve) {
      case Ecc.curve25519:
        final secret = Helper.secureRandom().nextBytes(
          TweetNaCl.secretKeyLength,
        );

        /// The highest bit must be 0 & the second highest bit must be 1
        secret[0] = (secret[0] & 0x7F) | 0x40;

        /// The lowest three bits must be 0
        secret[TweetNaCl.secretKeyLength - 1] &= 0xF8;
        final privateKey = nacl.PrivateKey(
          Uint8List.fromList(secret.reversed.toList()),
        );
        return ECDHSecretMaterial(
          Uint8List.fromList(
            privateKey.asTypedList.reversed.toList(),
          ).toBigIntWithSign(1),
          ECDHPublicMaterial(
            curve.asn1Oid,
            Uint8List.fromList([
              0x40,
              ...privateKey.publicKey.asTypedList,
            ]).toBigIntWithSign(1),
            curve.hashAlgorithm,
            curve.symmetricAlgorithm,
          ),
        );
      case Ecc.ed25519:
        throw UnsupportedError(
          'Curve ${curve.name} is unsupported for ECDH key generation.',
        );
      default:
        final keyPair = ECSecretMaterial.generateKeyPair(curve.name);
        final privateKey = keyPair.privateKey as ECPrivateKey;
        final q = (keyPair.publicKey as ECPublicKey).Q!;
        return ECDHSecretMaterial(
          privateKey.d!,
          ECDHPublicMaterial(
            curve.asn1Oid,
            q
                .getEncoded(
                  q.isCompressed,
                )
                .toBigIntWithSign(1),
            curve.hashAlgorithm,
            curve.symmetricAlgorithm,
          ),
        );
    }
  }

  @override
  int get keyLength => publicMaterial.keyLength;

  @override
  bool get isValid {
    switch (publicMaterial.curve) {
      case Ecc.curve25519:
        final privateKey = nacl.PrivateKey(
          Uint8List.fromList(d.toUnsignedBytes().reversed.toList()),
        );
        final dG = Uint8List.fromList([
          0x40,
          ...privateKey.publicKey.asTypedList,
        ]);
        return publicMaterial.q.compareTo(dG.toBigIntWithSign(1)) == 0;
      case Ecc.ed25519:
        return false;
      default:
        final parameters = ECDomainParameters(publicMaterial.curve.name.toLowerCase());
        final q = parameters.curve.decodePoint(publicMaterial.q.toUnsignedBytes());
        return q != null && !q.isInfinity && (parameters.G * d) == q;
    }
  }
}
