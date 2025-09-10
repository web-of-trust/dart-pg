/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:convert';
import 'dart:typed_data';

import '../../common/extensions.dart';
import '../../enum/signature_subpacket_type.dart';
import '../signature_subpacket.dart';

/// This subpacket contains a URI of a document that describes the policy
/// under which the signature was issued.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class PolicyURI extends SignatureSubpacket {
  PolicyURI(
    final Uint8List data, {
    super.critical,
  }) : super(SignatureSubpacketType.policyURI, data);

  factory PolicyURI.fromURI(
    final String uri, {
    final bool critical = false,
  }) =>
      PolicyURI(uri.toBytes(), critical: critical);

  String get uri => utf8.decode(data);
}
