// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enums.dart';
import '../signature_subpacket.dart';

class RevocationKey extends SignatureSubpacket {
  RevocationKey(Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.revocationKey, data);

  factory RevocationKey.fromRevocation(
    RevocationKeyTag signatureClass,
    KeyAlgorithm keyAlgorithm,
    Uint8List fingerprint, {
    bool critical = false,
  }) =>
      RevocationKey(_revocationToBytes(signatureClass, keyAlgorithm, fingerprint), critical: critical);

  int get signatureClass => data[0];

  int get keyAlgorithm => data[1];

  Uint8List get fingerprint => data.sublist(2);

  static Uint8List _revocationToBytes(
    RevocationKeyTag signatureClass,
    KeyAlgorithm keyAlgorithm,
    Uint8List fingerprint,
  ) {
    final List<int> bytes = [signatureClass.value, keyAlgorithm.value];
    bytes.addAll(fingerprint);
    return Uint8List.fromList(bytes);
  }
}
