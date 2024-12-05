/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';

import 'package:dart_pg/src/type/signature_packet.dart';
import 'package:dart_pg/src/type/verification.dart';

/// Verification class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class Verification implements VerificationInterface {
  @override
  final Uint8List keyID;

  @override
  final SignaturePacketInterface signaturePacket;

  @override
  final bool isVerified;

  @override
  final String verificationError;

  Verification(
    this.keyID,
    this.signaturePacket,
    this.isVerified,
    this.verificationError,
  );
}
