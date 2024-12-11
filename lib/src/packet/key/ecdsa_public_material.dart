/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import '../../common/helpers.dart';
import '../../enum/hash_algorithm.dart';
import '../../packet/key/ec_public_material.dart';
import '../../type/verification_key_material.dart';

/// ECDSA public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ECDSAPublicMaterial extends ECPublicMaterial
    implements VerificationKeyMaterial {
  ECDSAPublicMaterial(super.oid, super.q);

  factory ECDSAPublicMaterial.fromBytes(final Uint8List bytes) {
    final length = bytes[0];
    return ECDSAPublicMaterial(
      ASN1ObjectIdentifier.fromBytes(Uint8List.fromList([
        0x06,
        length,
        ...bytes.sublist(1, length + 1),
      ])),
      Helper.readMPI(bytes.sublist(length + 1)),
    );
  }

  @override
  verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) {
    final params = ECDomainParameters(curve.name.toLowerCase());
    final signer = Signer('${hash.digestName}/DET-ECDSA')
      ..init(
        false,
        PublicKeyParameter<ECPublicKey>(
          ECPublicKey(
            params.curve.decodePoint(q.toUnsignedBytes()),
            params,
          ),
        ),
      );

    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return signer.verifySignature(message, ECSignature(r, s));
  }
}
