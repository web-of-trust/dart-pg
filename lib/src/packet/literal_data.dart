// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../byte_utils.dart';
import '../enums.dart';
import 'contained_packet.dart';

/// LiteralData represents an encrypted file.
/// See RFC 4880, section 5.9.
class LiteralData extends ContainedPacket {
  final LiteralFormat format;

  final DateTime time;

  final Uint8List data;

  final String text;

  final String filename;

  LiteralData(
    this.data, {
    this.format = LiteralFormat.utf8,
    DateTime? creationTime,
    this.text = '',
    this.filename = '',
    super.tag = PacketTag.literalData,
  }) : time = creationTime ?? DateTime.now();

  factory LiteralData.fromPacketData(final Uint8List bytes) {
    var pos = 0;
    final format = LiteralFormat.values.firstWhere((format) => format.value == bytes[pos++]);
    final length = bytes[pos++];
    final filename = utf8.decode(bytes.sublist(pos, pos + length));

    pos += length;
    final time = ByteUtils.bytesToTime(bytes.sublist(pos, pos + 4));

    pos += 4;
    final data = bytes.sublist(pos);

    return LiteralData(
      data,
      format: format,
      filename: filename,
      creationTime: time,
      text: utf8.decode(data),
    );
  }

  @override
  Uint8List toPacketData() {
    final List<int> bytes = [
      format.value,
      filename.length,
      ...utf8.encode(filename),
      ...ByteUtils.timeToBytes(time),
    ];

    if (data.isNotEmpty) {
      bytes.addAll(data);
    } else if (text.isNotEmpty) {
      final normalizedText = LineSplitter.split(text).join('\r\n');
      bytes.addAll(utf8.encode(normalizedText));
    }

    return Uint8List.fromList(bytes);
  }
}
