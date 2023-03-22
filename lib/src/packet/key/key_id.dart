// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/byte_ext.dart';
import '../../helpers.dart';

class KeyID {
  final Uint8List bytes;

  KeyID(this.bytes);

  factory KeyID.fromString(final String id) => KeyID(id.hexToBytes());

  factory KeyID.wildcard() => KeyID(
        Uint8List.fromList(List.filled(8, 0, growable: false)),
      );

  String get id => bytes.toHexadecimal();

  @override
  String toString() => id;

  @override
  bool operator ==(other) {
    if (other is! KeyID) return false;
    return (other.bytes.equals(bytes));
  }

  @override
  int get hashCode {
    return bytes.hashCode;
  }
}
