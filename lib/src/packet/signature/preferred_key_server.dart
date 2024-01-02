// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enum/signature_subpacket_type.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PreferredKeyServer extends SignatureSubpacket {
  PreferredKeyServer(
    final Uint8List data, {
    super.critical,
    super.isLong,
  }) : super(SignatureSubpacketType.preferredKeyServer, data);

  factory PreferredKeyServer.fromKeyServer(
    final String keyServer, {
    final bool critical = false,
  }) =>
      PreferredKeyServer(keyServer.stringToBytes(), critical: critical);

  String get keyServer => utf8.decode(data);
}
