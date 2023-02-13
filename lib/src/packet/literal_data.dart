// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../enums.dart';
import '../helpers.dart';
import 'contained_packet.dart';

/// LiteralData represents an encrypted file.
/// See RFC 4880, section 5.9.
class LiteralDataPacket extends ContainedPacket {
  final LiteralFormat format;

  final DateTime time;

  final Uint8List data;

  final String text;

  final String filename;

  LiteralDataPacket(
    this.data, {
    this.format = LiteralFormat.utf8,
    DateTime? creationTime,
    this.text = '',
    this.filename = '',
    super.tag = PacketTag.literalData,
  }) : time = creationTime ?? DateTime.now();

  factory LiteralDataPacket.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final format = LiteralFormat.values.firstWhere((format) => format.value == bytes[pos]);
    pos++;
    final length = bytes[pos++];
    final filename = utf8.decode(bytes.sublist(pos, pos + length));

    pos += length;
    final time = bytes.sublist(pos, pos + 4).toDateTime();

    pos += 4;
    final data = bytes.sublist(pos);

    return LiteralDataPacket(
      data,
      format: format,
      filename: filename,
      creationTime: time,
      text: utf8.decode(data),
    );
  }

  @override
  Uint8List toPacketData() {
    return Uint8List.fromList([
      ...writeHeader(),
      ...data.isNotEmpty ? data : text.replaceAll(RegExp(r'\r?\n', multiLine: true), '\r\n').stringToBytes(),
    ]);
  }

  Uint8List writeHeader() {
    return Uint8List.fromList([
      format.value,
      filename.length,
      ...filename.stringToBytes(),
      ...time.toBytes(),
    ]);
  }
}
