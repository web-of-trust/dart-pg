// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// This is a list of one-bit flags that indicate preferences that the
/// key holder has about how the key is handled on a key server.
/// All undefined flags MUST be zero.
/// See https://www.rfc-editor.org/rfc/rfc4880#section-5.2.3.17
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class KeyServerPreferences extends SignatureSubpacket {
  KeyServerPreferences(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.keyServerPreferences, data);

  factory KeyServerPreferences.fromServerPreferences(
    final String serverPreferences, {
    final bool critical = false,
  }) =>
      KeyServerPreferences(
        serverPreferences.stringToBytes(),
        critical: critical,
      );

  String get serverPreferences => utf8.decode(data);
}
