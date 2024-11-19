/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This subpacket allows a keyholder to state which User ID is
/// responsible for the signing.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SignerUserID extends SignatureSubpacket {
  SignerUserID(final Uint8List data, {super.critical, super.isLong}) : super(SignatureSubpacketType.signerUserID, data);

  factory SignerUserID.fromUserID(
    final String userID, {
    final bool critical = false,
  }) =>
      SignerUserID(utf8.encoder.convert(userID), critical: critical);

  String get userID => utf8.decode(data);
}
