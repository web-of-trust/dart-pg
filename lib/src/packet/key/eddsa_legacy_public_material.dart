/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:pinenacl/ed25519.dart';
import 'package:pointycastle/asn1.dart';

import '../../common/helpers.dart';
import '../../enum/hash_algorithm.dart';
import '../../type/verification_key_material.dart';
import 'ec_public_material.dart';

/// EdDSA legacy public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class EdDSALegacyPublicMaterial extends ECPublicMaterial implements VerificationKeyMaterial {
  EdDSALegacyPublicMaterial(super.oid, super.q);

  factory EdDSALegacyPublicMaterial.fromBytes(final Uint8List bytes) {
    final length = bytes[0];
    return EdDSALegacyPublicMaterial(
      ASN1ObjectIdentifier.fromBytes(Uint8List.fromList([
        0x06,
        length,
        ...bytes.sublist(1, 1 + length),
      ])),
      Helper.readMPI(bytes.sublist(1 + length)),
    );
  }

  @override
  verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) {
    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return VerifyKey(q.toUnsignedBytes().sublist(1)).verify(
      signature: Signature(Uint8List.fromList([
        ...r.toUnsignedBytes(),
        ...s.toUnsignedBytes(),
      ])),
      message: Helper.hashDigest(message, hash),
    );
  }
}
