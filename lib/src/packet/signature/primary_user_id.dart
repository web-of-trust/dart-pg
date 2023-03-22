// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// packet giving whether or not the signature is signed using the primary user ID for the key.
class PrimaryUserID extends SignatureSubpacket {
  PrimaryUserID(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.primaryUserID, data);

  factory PrimaryUserID.fromIsPrimary(
    final bool isPrimary, {
    final bool critical = false,
  }) =>
      PrimaryUserID(Uint8List.fromList([isPrimary ? 1 : 0]), critical: critical);

  bool get isPrimary => data[0] != 0;
}
