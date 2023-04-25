// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../crypto/math/int_ext.dart';

class UserAttributeSubpacket {
  final int type;

  final Uint8List data;

  final bool isLong;

  UserAttributeSubpacket(this.type, this.data, {this.isLong = false});

  Uint8List encode() {
    final List<int> header;
    final bodyLen = data.length + 1;

    if (bodyLen < 192 && !isLong) {
      header = [bodyLen];
    } else if (bodyLen <= 8383 && !isLong) {
      header = [(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192];
    } else {
      header = [0xff, ...bodyLen.pack32()];
    }
    return Uint8List.fromList([...header, type, ...data]);
  }
}
