// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:math';
import 'dart:typed_data';

import '../enum/packet_tag.dart';
import '../crypto/math/int_ext.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
abstract class ContainedPacket {
  static const partialMinSize = 512;
  static const partialMaxSize = 1024;

  final PacketTag tag;

  ContainedPacket(this.tag);

  /// Serializes packet data to bytes
  Uint8List toByteData();

  /// Serializes packet to bytes
  Uint8List encode() {
    switch (tag) {
      case PacketTag.aeadEncryptedData:
      case PacketTag.compressedData:
      case PacketTag.literalData:
      case PacketTag.symEncryptedData:
      case PacketTag.symEncryptedIntegrityProtectedData:
        return _partialEncode();
      default:
        final bodyData = toByteData();
        return Uint8List.fromList([
          0xc0 | tag.value,
          ..._simpleLength(bodyData.length),
          ...bodyData,
        ]);
    }
  }

  /// Encode package to the openpgp partial body specifier
  Uint8List _partialEncode() {
    final List<int> partialData = [];
    var bodyData = toByteData();
    var dataLengh = bodyData.length;
    while (dataLengh >= partialMinSize) {
      final maxSize = min(partialMaxSize, dataLengh);
      final powerOf2 = min((log(maxSize) / ln2).toInt(), 30);
      final chunkSize = 1 << powerOf2;
      partialData.addAll(
        [
          224 + powerOf2,
          ...bodyData.sublist(0, chunkSize),
        ],
      );
      bodyData = bodyData.sublist(chunkSize);
      dataLengh = bodyData.length;
    }
    partialData.addAll([
      ..._simpleLength(dataLengh),
      ...bodyData,
    ]);
    return Uint8List.fromList([0xc0 | tag.value, ...partialData]);
  }

  List<int> _simpleLength(int length) {
    if (length < 192) {
      return [length];
    } else if (length < 8384) {
      return [(((length - 192) >> 8) & 0xff) + 192, length - 192];
    } else {
      return [0xff, ...length.pack32()];
    }
  }
}
