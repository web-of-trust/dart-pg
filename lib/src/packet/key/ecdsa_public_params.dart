// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../../crypto/math/big_int.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'ec_public_params.dart';
import 'verification_params.dart';

class ECDSAPublicParams extends ECPublicParams implements VerificationParams {
  ECDSAPublicParams(super.oid, super.q);

  factory ECDSAPublicParams.fromByteData(final Uint8List bytes) {
    final length = bytes[0];
    ECPublicParams.validateOidLength(length);
    return ECDSAPublicParams(
      ASN1ObjectIdentifier.fromBytes(Uint8List.fromList([
        0x06,
        length,
        ...bytes.sublist(1, length + 1),
      ])),
      Helper.readMPI(bytes.sublist(length + 1)),
    );
  }

  @override
  bool verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) {
    final parameters = ECDomainParameters(curve.name.toLowerCase());
    final signer = Signer('${hash.digestName}/DET-ECDSA')
      ..init(
        false,
        PublicKeyParameter<ECPublicKey>(
          ECPublicKey(
            parameters.curve.decodePoint(q.toUnsignedBytes()),
            parameters,
          ),
        ),
      );

    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    return signer.verifySignature(message, ECSignature(r, s));
  }
}
