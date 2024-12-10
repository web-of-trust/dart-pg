/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/pointycastle.dart';

import 'ec_public_material.dart';
import '../../common/helpers.dart';
import '../../enum/hash_algorithm.dart';
import '../../enum/symmetric_algorithm.dart';

/// ECDH public key material
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ECDHPublicMaterial extends ECPublicMaterial {
  final int reserved;

  /// Hash algorithm used with the KDF
  final HashAlgorithm kdfHash;

  /// symmetric algorithm used to
  /// wrap the symmetric key for message encryption
  final SymmetricAlgorithm kdfSymmetric;

  factory ECDHPublicMaterial.fromBytes(final Uint8List bytes) {
    var pos = 0;
    final length = bytes[pos++];

    final oid = ASN1ObjectIdentifier.fromBytes(Uint8List.fromList([
      0x06,
      length,
      ...bytes.sublist(pos, pos + length),
    ]));

    pos += length;
    final q = Helper.readMPI(bytes.sublist(pos));
    pos += q.byteLength + 2;

    final kdfBytes = bytes.sublist(pos);
    final reserved = kdfBytes[1];
    final kdfHash = HashAlgorithm.values.firstWhere(
      (hash) => hash.value == kdfBytes[2],
    );
    final kdfSymmetric = SymmetricAlgorithm.values.firstWhere(
      (sym) => sym.value == kdfBytes[3],
    );
    return ECDHPublicMaterial(
      oid,
      q,
      kdfHash,
      kdfSymmetric,
      reserved,
    );
  }

  ECDHPublicMaterial(
    super.oid,
    super.q,
    this.kdfHash,
    this.kdfSymmetric, [
    this.reserved = 0x1,
  ]);

  @override
  get toBytes => Uint8List.fromList([
        ...super.toBytes,
        0x3,
        reserved,
        kdfHash.value,
        kdfSymmetric.value,
      ]);
}
