/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Used in conjunction with trust Signature packets (of level > 0) to
/// limit the scope of trust that is extended.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class RegularExpression extends SignatureSubpacket {
  RegularExpression(final Uint8List data, {super.critical})
      : super(SignatureSubpacketType.revocable, data);

  factory RegularExpression.fromExpression(
    final String expression, {
    final bool critical = false,
  }) =>
      RegularExpression(expression.toBytes(), critical: critical);

  String get expression => utf8.decode(data);
}
