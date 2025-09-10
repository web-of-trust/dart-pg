/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../common/extensions.dart';

/// User attribute subpacket
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class UserAttributeSubpacket {
  final int type;

  final Uint8List data;

  UserAttributeSubpacket(this.type, this.data);

  Uint8List encode() {
    final List<int> header;
    final bodyLen = data.length + 1;

    if (bodyLen < 192) {
      header = [bodyLen];
    } else if (bodyLen <= 8383) {
      header = [(((bodyLen - 192) >> 8) & 0xff) + 192, bodyLen - 192];
    } else {
      header = [0xff, ...bodyLen.pack32()];
    }
    return Uint8List.fromList([...header, type, ...data]);
  }
}
