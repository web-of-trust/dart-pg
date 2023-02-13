// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:typed_data';

import '../../enums.dart';
import '../../helpers.dart';
import '../signature_subpacket.dart';

class PolicyURI extends SignatureSubpacket {
  PolicyURI(Uint8List data, {super.critical, super.isLongLength}) : super(SignatureSubpacketType.policyURI, data);

  factory PolicyURI.fromURI(String uri, {bool critical = false}) => PolicyURI(uri.stringToBytes(), critical: critical);

  String get uri => utf8.decode(data);
}
