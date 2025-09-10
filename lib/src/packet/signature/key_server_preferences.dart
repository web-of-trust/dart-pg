/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This is a list of one-bit flags that indicate preferences that the
/// key holder has about how the key is handled on a key server.
/// All undefined flags MUST be zero.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class KeyServerPreferences extends SignatureSubpacket {
  KeyServerPreferences(
    final Uint8List data, {
    super.critical,
  }) : super(SignatureSubpacketType.keyServerPreferences, data);

  factory KeyServerPreferences.fromServerPreferences(
    final String serverPreferences, {
    final bool critical = false,
  }) =>
      KeyServerPreferences(
        serverPreferences.toBytes(),
        critical: critical,
      );

  String get serverPreferences => utf8.decode(data);
}
