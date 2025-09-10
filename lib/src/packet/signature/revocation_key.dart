/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/key_algorithm.dart';
import '../../enum/revocation_key_tag.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Authorizes the specified key to issue revocation signatures for this key.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class RevocationKey extends SignatureSubpacket {
  RevocationKey(final Uint8List data, {super.critical})
      : super(SignatureSubpacketType.revocationKey, data);

  factory RevocationKey.fromRevocation(
    final RevocationKeyTag signatureClass,
    final KeyAlgorithm keyAlgorithm,
    final Uint8List fingerprint, {
    final bool critical = false,
  }) =>
      RevocationKey(
        _revocationToBytes(signatureClass, keyAlgorithm, fingerprint),
        critical: critical,
      );

  RevocationKeyTag get signatureClass => RevocationKeyTag.values.firstWhere(
        (tag) => tag.value == data[0],
      );

  KeyAlgorithm get keyAlgorithm => KeyAlgorithm.values.firstWhere(
        (alg) => alg.value == data[1],
      );

  String get fingerprint => data.sublist(2).toHexadecimal();

  static Uint8List _revocationToBytes(
    final RevocationKeyTag signatureClass,
    final KeyAlgorithm keyAlgorithm,
    final Uint8List fingerprint,
  ) =>
      Uint8List.fromList([
        signatureClass.value,
        keyAlgorithm.value,
        ...fingerprint,
      ]);
}
