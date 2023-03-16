// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'package:pinenacl/ed25519.dart';
import 'package:pointycastle/asn1.dart';

import '../../crypto/math/big_int.dart';
import '../../enum/hash_algorithm.dart';
import '../../helpers.dart';
import 'key_params.dart';

class EdDSAPublicParams extends ECPublicParams {
  EdDSAPublicParams(super.oid, super.q);

  factory EdDSAPublicParams.fromByteData(final Uint8List bytes) {
    var pos = 0;
    final length = bytes[pos++];
    ECPublicParams.validateOidLength(length);
    return EdDSAPublicParams(
      ASN1ObjectIdentifier.fromBytes(Uint8List.fromList([
        0x06,
        length,
        ...bytes.sublist(pos, pos + length),
      ])),
      Helper.readMPI(bytes.sublist(pos + length)),
    );
  }

  bool verify(
    final Uint8List message,
    final HashAlgorithm hash,
    final Uint8List signature,
  ) {
    final r = Helper.readMPI(signature);
    final s = Helper.readMPI(signature.sublist(r.byteLength + 2));

    final verifyKey = VerifyKey(q.toUnsignedBytes().sublist(1));
    return verifyKey.verify(
      signature: Signature(Uint8List.fromList([
        ...r.toUnsignedBytes(),
        ...s.toUnsignedBytes(),
      ])),
      message: Helper.hashDigest(message, hash),
    );
  }
}
