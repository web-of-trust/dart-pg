/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import '../../enum/key_flag.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This subpacket contains a list of binary flags that hold information about a key.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class KeyFlags extends SignatureSubpacket {
  KeyFlags(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.keyFlags, data);

  factory KeyFlags.fromFlags(
    final int flags, {
    final bool critical = false,
  }) =>
      KeyFlags(_flagsToBytes(flags), critical: critical);

  /// Return the flag values contained in the first 4 octets
  /// (note: at the moment the standard only uses the first one).
  int get flags {
    var value = 0;
    for (var i = 0; i != data.length; i++) {
      value |= data[i] << (i * 8);
    }
    return value;
  }

  bool get isCertifyKeys =>
      flags & KeyFlag.certifyKeys.value == KeyFlag.certifyKeys.value;

  bool get isSignData =>
      flags & KeyFlag.signData.value == KeyFlag.signData.value;

  bool get isEncryptCommunication =>
      flags & KeyFlag.encryptCommunication.value ==
      KeyFlag.encryptCommunication.value;

  bool get isEncryptStorage =>
      flags & KeyFlag.encryptStorage.value == KeyFlag.encryptStorage.value;

  static Uint8List _flagsToBytes(final int flags) {
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
