/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/extensions.dart';
import '../enum/signature_subpacket_type.dart';
import '../type/subpacket.dart';

export 'signature/embedded_signature.dart';
export 'signature/exportable_certification.dart';
export 'signature/features.dart';
export 'signature/issuer_fingerprint.dart';
export 'signature/issuer_key_id.dart';
export 'signature/key_expiration_time.dart';
export 'signature/key_flags.dart';
export 'signature/key_server_preferences.dart';
export 'signature/notation_data.dart';
export 'signature/policy_uri.dart';
export 'signature/preferred_aead_algorithms.dart';
export 'signature/preferred_compression_algorithms.dart';
export 'signature/preferred_hash_algorithms.dart';
export 'signature/preferred_key_server.dart';
export 'signature/preferred_symmetric_algorithms.dart';
export 'signature/primary_user_id.dart';
export 'signature/regular_expression.dart';
export 'signature/revocable.dart';
export 'signature/revocation_key.dart';
export 'signature/revocation_reason.dart';
export 'signature/signature_creation_time.dart';
export 'signature/signature_expiration_time.dart';
export 'signature/signature_target.dart';
export 'signature/signer_user_id.dart';
export 'signature/trust_signature.dart';

/// Signature subpacket class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SignatureSubpacket implements SubpacketInterface {
  @override
  final SignatureSubpacketType type;

  @override
  final bool isLong;

  @override
  final Uint8List data;

  final bool critical;

  SignatureSubpacket(
    this.type,
    this.data, {
    this.critical = false,
    this.isLong = false,
  });

  @override
  Uint8List encode() {
    final List<int> header;
    final bodyLen = data.length + 1;

    if (isLong) {
      header = [0xff, ...bodyLen.pack32()];
    } else {
      if (bodyLen < 192) {
        header = [bodyLen];
      } else if (bodyLen <= 8383) {
        header = [(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192];
      } else {
        header = [0xff, ...bodyLen.pack32()];
      }
    }

    return Uint8List.fromList([
      ...header,
      critical ? type.value | 0x80 : type.value,
      ...data,
    ]);
  }
}
