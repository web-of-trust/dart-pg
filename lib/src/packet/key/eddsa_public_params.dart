// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';

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
}
