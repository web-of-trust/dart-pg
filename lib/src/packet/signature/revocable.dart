/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Signature's revocability status. The packet body contains a
/// Boolean flag indicating whether the signature is revocable.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Revocable extends SignatureSubpacket {
  Revocable(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.revocable, data);

  factory Revocable.fromRevocable(
    final bool isRevocable, {
    final bool critical = false,
  }) =>
      Revocable(
        Uint8List.fromList([isRevocable ? 1 : 0]),
        critical: critical,
      );

  bool get isRevocable => data[0] != 0;
}
