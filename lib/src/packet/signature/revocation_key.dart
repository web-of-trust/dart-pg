// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:dart_pg/src/helpers.dart';

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

  RevocationKeyTag get signatureClass => RevocationKeyTag.values.firstWhere((tag) => tag.value == data[0]);

  KeyAlgorithm get keyAlgorithm => KeyAlgorithm.values.firstWhere((alg) => alg.value == data[1]);

  String get fingerprint => data.sublist(2).toHexadecimal();

  static Uint8List _revocationToBytes(
    RevocationKeyTag signatureClass,
    KeyAlgorithm keyAlgorithm,
    Uint8List fingerprint,
  ) =>
      Uint8List.fromList([signatureClass.value, keyAlgorithm.value, ...fingerprint]);
}
