/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// The IntendedRecipientFingerprint sub-packet class
/// Giving the intended recipient fingerprint.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PreferredAeadCiphers extends SignatureSubpacket {
  PreferredAeadCiphers(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(
          SignatureSubpacketType.preferredAeadCiphers,
          data,
        );
}
