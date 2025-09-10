/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This is a URI of a key server that the key holder prefers be used for updates.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class PreferredKeyServer extends SignatureSubpacket {
  PreferredKeyServer(
    final Uint8List data, {
    super.critical,
  }) : super(SignatureSubpacketType.preferredKeyServer, data);

  factory PreferredKeyServer.fromKeyServer(
    final String keyServer, {
    final bool critical = false,
  }) =>
      PreferredKeyServer(keyServer.toBytes(), critical: critical);

  String get keyServer => utf8.decode(data);
}
