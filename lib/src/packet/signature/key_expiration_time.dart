// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../enums.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// packet giving time after creation at which the key expires.
class KeyExpirationTime extends SignatureSubpacket {
  KeyExpirationTime(Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.keyExpirationTime, data);

  factory KeyExpirationTime.fromTime(int seconds, {bool critical = false}) =>
      KeyExpirationTime(seconds.pack32(), critical: critical);

  /// Return the number of seconds after creation time a key is valid for.
  int get time => data.toUint32();
}
