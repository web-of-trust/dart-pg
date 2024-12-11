/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This is a flag in a User ID's self-signature that states whether this
/// User ID is the main User ID for this key.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PrimaryUserID extends SignatureSubpacket {
  PrimaryUserID(final Uint8List data, {super.critical, super.isLong})
      : super(SignatureSubpacketType.primaryUserID, data);

  factory PrimaryUserID.fromIsPrimary(
    final bool isPrimary, {
    final bool critical = false,
  }) =>
      PrimaryUserID(Uint8List.fromList([isPrimary ? 1 : 0]),
          critical: critical);

  bool get isPrimary => data[0] != 0;
}
