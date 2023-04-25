// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/byte_ext.dart';
import '../../enum/signature_subpacket_type.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

class SignatureCreationTime extends SignatureSubpacket {
  SignatureCreationTime(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.signatureCreationTime, data);

  factory SignatureCreationTime.fromTime(
    final DateTime time, {
    final bool critical = false,
  }) =>
      SignatureCreationTime(time.toBytes(), critical: critical);

  DateTime get creationTime => data.toDateTime();
}
