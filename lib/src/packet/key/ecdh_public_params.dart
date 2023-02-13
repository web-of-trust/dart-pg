// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/pointycastle.dart';

import '../../enums.dart';
import '../../helpers.dart';
import 'ec_public_params.dart';

class ECDHPublicParams extends ECPublicParams {
  final int reserved;

  final HashAlgorithm kdfHash;

  final SymmetricAlgorithm kdfSymmetric;

  ECDHPublicParams(super.oid, super.q, this.kdfHash, this.kdfSymmetric, [this.reserved = 0x1]);

  factory ECDHPublicParams.fromPacketData(Uint8List bytes) {
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
    pos += q.byteLength + 2;

    final kdfBytes = bytes.sublist(pos);
    final reserved = kdfBytes[1];
    final kdfHash = HashAlgorithm.values.firstWhere((hash) => hash.value == kdfBytes[2]);
    final kdfSymmetric = SymmetricAlgorithm.values.firstWhere((sym) => sym.value == kdfBytes[3]);
    return ECDHPublicParams(
      oid,
      q,
      kdfHash,
      kdfSymmetric,
      reserved,
    );
  }

  @override
  Uint8List encode() => Uint8List.fromList([
        ...super.encode(),
        ...[
          0x3,
          reserved,
          kdfHash.value,
          kdfSymmetric.value,
        ]
      ]);
}
