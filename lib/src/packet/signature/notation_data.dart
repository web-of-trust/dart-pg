/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../../common/helpers.dart';
import '../../enum/signature_subpacket_type.dart';
import '../../type/notation_data.dart';
import '../signature_subpacket.dart';

/// This subpacket describes a "notation" on the signature that the issuer wishes to make.
/// The notation has a name and a value, each of which are strings of octets.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class NotationData extends SignatureSubpacket implements NotationDataInterface {
  static const saltName = "salt@notations.dart-pg.org";

  static const headerFlagLength = 4;
  static const headerNameLength = 2;
  static const headerValueLength = 2;

  NotationData(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.notationData, data);

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

  factory NotationData.saltNotation(
    int saltSize, {
    final bool critical = false,
  }) {
    final valueData = Helper.generatePassword(saltSize).toBytes();
    final nameData = saltName.toBytes();
    final nameLength = min(nameData.length, 0xffff);
    return NotationData(
      Uint8List.fromList([
        ...[0, 0, 0, 0],
        (nameLength >> 8) & 0xff,
        (nameLength >> 0) & 0xff,
        (valueData.length >> 8) & 0xff,
        (valueData.length >> 0) & 0xff,
        ...nameData,
        ...valueData,
      ]),
      critical: critical,
    );
  }

  @override
  String get notationName => utf8.decode(nameData);

  @override
  String get notationValue => utf8.decode(valueData);

  @override
  bool get isHumanReadable => data[0] == 0x80;

  Uint8List get nameData {
    final nameLength = (((data[headerFlagLength] & 0xff) << 8) + (data[headerFlagLength + 1] & 0xff));
    final nameOffset = headerFlagLength + headerNameLength + headerValueLength;
    return data.sublist(nameOffset, nameOffset + nameLength);
  }

  Uint8List get valueData {
    final nameLength = (((data[headerFlagLength] & 0xff) << 8) + (data[headerFlagLength + 1] & 0xff));
    final valueLength = (((data[headerFlagLength + headerNameLength] & 0xff) << 8) +
        (data[headerFlagLength + headerNameLength + 1] & 0xff));
    final valueOffset = headerFlagLength + headerNameLength + headerValueLength + nameLength;
    return data.sublist(valueOffset, valueOffset + valueLength);
  }

  static Uint8List _notationToBytes(
    final bool humanReadable,
    final String notationName,
    final String notationValue,
  ) {
    final nameData = notationName.toBytes();
    final nameLength = min(nameData.length, 0xffff);
    if (nameLength != nameData.length) {
      throw ArgumentError('notationName exceeds maximum length.');
    }
    final valueData = notationValue.toBytes();
    final valueLength = min(valueData.length, 0xffff);
    if (valueLength != valueData.length) {
      throw ArgumentError('notationValue exceeds maximum length.');
    }

    return Uint8List.fromList([
      ...[humanReadable ? 0x80 : 0, 0, 0, 0],
      (nameLength >> 8) & 0xff,
      (nameLength >> 0) & 0xff,
      (valueLength >> 8) & 0xff,
      (valueLength >> 0) & 0xff,
      ...nameData.sublist(0, nameLength),
      ...valueData.sublist(0, valueLength),
    ]);
  }
}
