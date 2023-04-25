// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// packet giving the User ID of the signer.
class SignerUserID extends SignatureSubpacket {
  SignerUserID(final Uint8List data, {super.critical, super.isLong})
      : super(SignatureSubpacketType.signerUserID, data);

  factory SignerUserID.fromUserID(
    final String userID, {
    final bool critical = false,
  }) =>
      SignerUserID(utf8.encoder.convert(userID), critical: critical);

  String get userID => utf8.decode(data);
}
