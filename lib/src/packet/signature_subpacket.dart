// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';

export 'signature/embedded_signature.dart';
export 'signature/exportable_certification.dart';
export 'signature/features.dart';
export 'signature/issuer_fingerprint.dart';
export 'signature/issuer_key_id.dart';
export 'signature/key_expiration_time.dart';
export 'signature/key_flags.dart';
export 'signature/notation_data.dart';
export 'signature/preferred_compression_algorithms.dart';
export 'signature/preferred_hash_algorithms.dart';
export 'signature/preferred_symmetric_algorithms.dart';
export 'signature/primary_user_id.dart';
export 'signature/revocable.dart';
export 'signature/revocation_key.dart';
export 'signature/revocation_reason.dart';
export 'signature/signature_creation_time.dart';
export 'signature/signature_expiration_time.dart';
export 'signature/signature_target.dart';
export 'signature/signer_user_id.dart';
export 'signature/trust_signature.dart';

class SignatureSubpacket {
  final SignatureSubpacketType type;

  final bool critical;

  final bool isLongLength;

  final Uint8List data;

  SignatureSubpacket(this.type, this.data, {this.critical = false, this.isLongLength = false});

  Uint8List write() {
    final List<int> bytes = [];
    final bodyLen = data.length + 1;

    if (isLongLength) {
      bytes.addAll([0xff, ...bodyLen.pack32()]);
    } else {
      if (bodyLen < 192) {
        bytes.add(bodyLen);
      } else if (bodyLen <= 8383) {
        bytes.addAll([(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192]);
      } else {
        bytes.addAll([0xff, ...bodyLen.pack32()]);
      }
    }

    bytes.addAll([critical ? 0x80 | type.value : type.value, ...data]);

    return Uint8List.fromList(bytes);
  }
}
