// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class RegularExpression extends SignatureSubpacket {
  RegularExpression(final Uint8List data, {super.critical, super.isLong})
      : super(SignatureSubpacketType.revocable, data);

  factory RegularExpression.fromExpression(
    final String expression, {
    final bool critical = false,
  }) =>
      RegularExpression(expression.stringToBytes(), critical: critical);

  String get expression => utf8.decode(data);
}
