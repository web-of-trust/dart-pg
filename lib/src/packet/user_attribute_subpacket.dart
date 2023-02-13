// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../helpers.dart';

class UserAttributeSubpacket {
  final int type;

  final Uint8List data;

  final bool isLongLength;

  UserAttributeSubpacket(this.type, this.data, {this.isLongLength = false});

  Uint8List toSubpacket() {
    final List<int> header;
    final bodyLen = data.length + 1;

    if (bodyLen < 192 && !isLongLength) {
      header = [bodyLen];
    } else if (bodyLen <= 8383 && !isLongLength) {
      header = [(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192];
    } else {
      header = [0xff, ...bodyLen.pack32()];
    }
    return Uint8List.fromList([...header, type, ...data]);
  }
}
