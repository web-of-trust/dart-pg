// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// packet giving signature expiration time.
class SignatureExpirationTime extends SignatureSubpacket {
  SignatureExpirationTime(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.signatureExpirationTime, data);

  factory SignatureExpirationTime.fromExpirationTime(final DateTime time, {final bool critical = false}) =>
      SignatureExpirationTime(time.toBytes(), critical: critical);

  DateTime get expirationTime => data.toDateTime();
}
