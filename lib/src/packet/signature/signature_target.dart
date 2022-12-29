// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enums.dart';
import '../signature_subpacket.dart';

/// RFC 4880, Section 5.2.3.25 - Signature Target subpacket.
class SignatureTarget extends SignatureSubpacket {
  SignatureTarget(Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.signatureTarget, data);

  factory SignatureTarget.fromHashData(
    KeyAlgorithm keyAlgorithm,
    HashAlgorithm hashAlgorithm,
    Uint8List hashData, {
    bool critical = false,
  }) =>
      SignatureTarget(_hashDataBytes(keyAlgorithm, hashAlgorithm, hashData), critical: critical);

  int get keyAlgorithm => data[0];

  int get hashAlgorithm => data[1];

  Uint8List get hashData => data.sublist(2);

  static Uint8List _hashDataBytes(
    KeyAlgorithm keyAlgorithm,
    HashAlgorithm hashAlgorithm,
    Uint8List hashData,
  ) {
    final List<int> bytes = [keyAlgorithm.value, hashAlgorithm.value];
    bytes.addAll(hashData);
    return Uint8List.fromList(bytes);
  }
}
