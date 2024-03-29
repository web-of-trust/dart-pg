// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../../crypto/math/byte_ext.dart';
import '../../crypto/math/int_ext.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// The validity period of the key. This is the number of seconds after
/// the key creation time that the key expires. If this is not present
/// or has a value of zero, the key never expires. This is found only on
/// a self-signature.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.6
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class KeyExpirationTime extends SignatureSubpacket {
  KeyExpirationTime(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.keyExpirationTime, data);

  factory KeyExpirationTime.fromTime(
    final int seconds, {
    final bool critical = false,
  }) =>
      KeyExpirationTime(seconds.pack32(), critical: critical);

  /// Return the number of seconds after creation time a key is valid for.
  int get time => data.toUint32();
}
