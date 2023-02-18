// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enums.dart';
import '../signature_subpacket.dart';

/// Packet holding the key flag values.
class KeyFlags extends SignatureSubpacket {
  KeyFlags(Uint8List data, {super.critical, super.isLongLength}) : super(SignatureSubpacketType.keyFlags, data);

  factory KeyFlags.fromFlags(int flags, {bool critical = false}) => KeyFlags(_flagsToBytes(flags), critical: critical);

  /// Return the flag values contained in the first 4 octets
  /// (note: at the moment the standard only uses the first one).
  int get flags {
    var value = 0;
    for (var i = 0; i != data.length; i++) {
      value |= data[i] << (i * 8);
    }
    return value;
  }

  static Uint8List _flagsToBytes(int flags) {
    final bytes = Uint8List(4);
    var size = 0;
    for (int i = 0; i != 4; i++) {
      bytes[i] = (flags >> (i * 8)) & 0xff;
      if (bytes[i] != 0) {
        size = i;
      }
    }
    return bytes.sublist(0, size + 1);
  }
}
