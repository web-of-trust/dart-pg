// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// Class provided a NotationData object according to RFC2440, Chapter 5.2.3.15. Notation Data
class NotationData extends SignatureSubpacket {
  static const headerFlagLength = 4;
  static const headerNameLength = 2;
  static const headerValueLength = 2;

  NotationData(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.notationData, data);

  factory NotationData.fromNotation(
    final bool humanReadable,
    final String notationName,
    final String notationValue, {
    final bool critical = false,
  }) =>
      NotationData(
        _notationToBytes(humanReadable, notationName, notationValue),
        critical: critical,
      );

  bool get isHumanReadable => data[0] == 0x80;

  String get notationName {
    final nameLength = (((data[headerFlagLength] & 0xff) << 8) +
        (data[headerFlagLength + 1] & 0xff));
    final nameOffset = headerFlagLength + headerNameLength + headerValueLength;
    return utf8.decode(data.sublist(nameOffset, nameOffset + nameLength));
  }

  String get notationValue {
    final nameLength = (((data[headerFlagLength] & 0xff) << 8) +
        (data[headerFlagLength + 1] & 0xff));
    final valueLength =
        (((data[headerFlagLength + headerNameLength] & 0xff) << 8) +
            (data[headerFlagLength + headerNameLength + 1] & 0xff));
    final valueOffset =
        headerFlagLength + headerNameLength + headerValueLength + nameLength;
    return utf8.decode(data.sublist(valueOffset, valueOffset + valueLength));
  }

  static Uint8List _notationToBytes(
    final bool humanReadable,
    final String notationName,
    final String notationValue,
  ) {
    final nameData = utf8.encode(notationName);
    final nameLength = min(nameData.length, 0xffff);
    if (nameLength != nameData.length) {
      throw Exception('notationName exceeds maximum length.');
    }

    final valueData = utf8.encode(notationValue);
    final valueLength = min(valueData.length, 0xffff);
    if (valueLength != valueData.length) {
      throw Exception('notationValue exceeds maximum length.');
    }

    return Uint8List.fromList([
      ...[humanReadable ? 0x80 : 0x00, 0x0, 0x0, 0x0],
      (nameLength >> 8) & 0xff,
      (nameLength >> 0) & 0xff,
      (valueLength >> 8) & 0xff,
      (valueLength >> 0) & 0xff,
      ...nameData.sublist(0, nameLength),
      ...valueData.sublist(0, valueLength),
    ]);
  }
}
