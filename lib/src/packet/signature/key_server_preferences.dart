// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enums.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

class KeyServerPreferences extends SignatureSubpacket {
  KeyServerPreferences(final Uint8List data, {super.critical, super.isLongLength})
      : super(SignatureSubpacketType.keyServerPreferences, data);

  factory KeyServerPreferences.fromServerPreferences(final String serverPreferences, {final bool critical = false}) =>
      KeyServerPreferences(serverPreferences.stringToBytes(), critical: critical);

  String get serverPreferences => utf8.decode(data);
}
