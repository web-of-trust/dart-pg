/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// The time the signature was made.
/// MUST be present in the hashed area.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class SignatureCreationTime extends SignatureSubpacket {
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
