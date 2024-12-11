/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/hash_algorithm.dart';
import '../../enum/key_algorithm.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This subpacket identifies a specific target signature to which a signature refers.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class SignatureTarget extends SignatureSubpacket {
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
