// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import '../packet/literal_data.dart';
import '../packet/packet_list.dart';
import 'key.dart';
import 'signature.dart';
import 'verification.dart';

class CleartextMessage {
  /// The cleartext of the signed message
  final String _text;

  CleartextMessage(String text) : _text = text.trimRight().replaceAll(RegExp(r'\r?\n', multiLine: true), '\r\n');

  String get text => _text;

  String get normalizeText => _text.replaceAll(RegExp(r'\r\n', multiLine: true), '\n');

  /// Verify detached message signature
  List<Verification> verifyDetached(
    final Signature signature,
    final List<PublicKey> verificationKeys, {
    final DateTime? date,
    final bool detached = false,
  }) {
    if (verificationKeys.isEmpty) {
      throw ArgumentError('No verification keys provided');
    }
    final verifications = <Verification>[];
    final literalData = LiteralDataPacket(Uint8List(0), text: text);

    for (final signaturePacket in signature.signaturePackets) {
      for (final key in verificationKeys) {
        final keyPacket = key.getSigningKeyPacket(keyID: signaturePacket.issuerKeyID.keyID);
        verifications.add(Verification(
          keyPacket.keyID.keyID,
          Signature(PacketList([signaturePacket])),
          signaturePacket.verifyLiteralData(keyPacket, literalData),
        ));
      }
    }

    return verifications;
  }
}
