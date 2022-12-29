// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../byte_utils.dart';
import '../../enums.dart';
import '../signature_subpacket.dart';

/// packet giving signature expiration time.
class SignatureExpirationTime extends SignatureSubpacket {
  SignatureExpirationTime(Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.signatureExpirationTime, data);

  factory SignatureExpirationTime.fromExpirationTime(DateTime time, {bool critical = false}) =>
      SignatureExpirationTime(ByteUtils.timeToBytes(time), critical: critical);

  DateTime get expirationTime => ByteUtils.bytesToTime(data);
}
