/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../common/helpers.dart';
import '../enum/packet_type.dart';
import '../enum/literal_format.dart';
import '../type/literal_data.dart';
import 'base.dart';

/// Implementation of the Literal Data Packet (Tag 11)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class LiteralDataPacket extends BasePacket implements LiteralDataInterface {
  @override
  final LiteralFormat format;

  @override
  final DateTime time;

  @override
  final Uint8List binary;

  @override
  final String text;

  @override
  final String filename;

  LiteralDataPacket(
    this.binary, {
    this.format = LiteralFormat.binary,
    final DateTime? time,
    this.text = '',
    this.filename = '',
  })  : time = time ?? DateTime.now(),
        super(PacketType.literalData);

  factory LiteralDataPacket.fromBytes(final Uint8List bytes) {
    var pos = 0;
    final format = LiteralFormat.values.firstWhere(
      (format) => format.value == bytes[pos],
    );
    pos++;
    final length = bytes[pos++];
    final filename = utf8.decode(bytes.sublist(pos, pos + length));

    pos += length;
    final time = bytes.sublist(pos, pos + 4).toDateTime();

    pos += 4;
    final data = bytes.sublist(pos);
    final text = switch (format) {
      LiteralFormat.text || LiteralFormat.utf8 => utf8.decode(data),
      _ => '',
    };

    return LiteralDataPacket(
      data,
      format: format,
      filename: filename,
      time: time,
      text: text,
    );
  }

  factory LiteralDataPacket.fromText(
    final String text, {
    final DateTime? time,
  }) =>
      LiteralDataPacket(
        Uint8List(0),
        text: text,
        format: LiteralFormat.utf8,
        time: time,
      );

  @override
  Uint8List get data => Uint8List.fromList([
        ...header,
        ...signBytes,
      ]);

  @override
  Uint8List get signBytes => binary.isNotEmpty
      ? binary
      : text
          .replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '\r\n',
          )
          .toBytes();

  @override
  Uint8List get header => Uint8List.fromList([
        format.value,
        filename.length,
        ...filename.toBytes(),
        ...time.toBytes(),
      ]);
}
