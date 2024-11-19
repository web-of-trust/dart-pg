/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/extensions.dart';
import '../enum/signature_subpacket_type.dart';
import '../type/subpacket.dart';

/// Signature subpacket class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class SignatureSubpacket implements SubpacketInterface {
  @override
  final SignatureSubpacketType type;

  @override
  final bool isLong;

  @override
  final Uint8List data;

  final bool critical;

  SignatureSubpacket(
    this.type,
    this.data, {
    this.critical = false,
    this.isLong = false,
  });

  @override
  Uint8List encode() {
    final List<int> header;
    final bodyLen = data.length + 1;

    if (isLong) {
      header = [0xff, ...bodyLen.pack32()];
    } else {
      if (bodyLen < 192) {
        header = [bodyLen];
      } else if (bodyLen <= 8383) {
        header = [(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192];
      } else {
        header = [0xff, ...bodyLen.pack32()];
      }
    }

    return Uint8List.fromList([
      ...header,
      critical ? type.value | 0x80 : type.value,
      ...data,
    ]);
  }
}
