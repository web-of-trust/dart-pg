// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:developer';

import '../packet/literal_data.dart';
import '../packet/packet_list.dart';
import '../packet/signature_packet.dart';
import 'key.dart';
import 'signature.dart';

/// Class that represents validity of signature.
class Verification {
  final String keyID;

  final Signature signature;

  final bool verified;

  Verification(this.keyID, this.signature, this.verified);

  static List<Verification> createVerifications(
    final LiteralDataPacket literalData,
    final Iterable<SignaturePacket> signaturePackets,
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) {
    if (verificationKeys.isEmpty) {
      throw ArgumentError('No verification keys provided');
    }
    final verifications = <Verification>[];
    for (var signaturePacket in signaturePackets) {
      for (final key in verificationKeys) {
        try {
          final keyPacket = key.getVerificationKeyPacket(keyID: signaturePacket.issuerKeyID.id);
          verifications.add(Verification(
            keyPacket.keyID.id,
            Signature(PacketList([signaturePacket])),
            signaturePacket.verifyLiteralData(
              keyPacket,
              literalData,
              date: date,
            ),
          ));
        } on Error catch (e) {
          log(e.toString(), error: e, stackTrace: e.stackTrace);
        }
      }
    }
    return verifications;
  }
}
