// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/hash_algorithm.dart';
import '../../enum/key_algorithm.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// RFC 4880, Section 5.2.3.25 - Signature Target subpacket.
class SignatureTarget extends SignatureSubpacket {
  SignatureTarget(final Uint8List data, {super.critical, super.isLong})
      : super(SignatureSubpacketType.signatureTarget, data);

  factory SignatureTarget.fromHashData(
    final KeyAlgorithm keyAlgorithm,
    final HashAlgorithm hashAlgorithm,
    final Uint8List hashData, {
    final bool critical = false,
  }) =>
      SignatureTarget(
        _hashDataBytes(keyAlgorithm, hashAlgorithm, hashData),
        critical: critical,
      );

  KeyAlgorithm get keyAlgorithm => KeyAlgorithm.values.firstWhere(
        (alg) => alg.value == data[0],
      );

  HashAlgorithm get hashAlgorithm => HashAlgorithm.values.firstWhere(
        (alg) => alg.value == data[1],
      );

  Uint8List get hashData => data.sublist(2);

  static Uint8List _hashDataBytes(
    final KeyAlgorithm keyAlgorithm,
    final HashAlgorithm hashAlgorithm,
    final Uint8List hashData,
  ) =>
      Uint8List.fromList([
        keyAlgorithm.value,
        hashAlgorithm.value,
        ...hashData,
      ]);
}
