// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../helpers.dart';
import 'ec_public_params.dart';

class ECDSAPublicParams extends ECPublicParams {
  ECDSAPublicParams(super.oid, super.q);

  factory ECDSAPublicParams.fromPacketData(Uint8List bytes) {
    var pos = 0;
    final length = bytes[pos++];
    if (length == 0 || length == 0xFF) {
      throw Exception('Future extensions not yet implemented');
    }
    if (length > 127) {
      throw UnsupportedError('Unsupported OID');
    }

    final derBytes = [0x06, length, ...bytes.sublist(pos, pos + length)];
    final oid = ASN1ObjectIdentifier.fromBytes(Uint8List.fromList(derBytes));

    pos += length;
    final q = Helper.readMPI(bytes.sublist(pos));
    return ECDSAPublicParams(oid, q);
  }
}
