/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// The validity period of the signature. This is the number of seconds
/// after the signature creation time that the signature expires.
/// If this is not present or has a value of zero, it never expires.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SignatureExpirationTime extends SignatureSubpacket {
  SignatureExpirationTime(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.signatureExpirationTime, data);

  factory SignatureExpirationTime.fromExpirationTime(
    final DateTime time, {
    final bool critical = false,
  }) =>
      SignatureExpirationTime(time.toBytes(), critical: critical);

  DateTime get expirationTime => data.toDateTime();
}
