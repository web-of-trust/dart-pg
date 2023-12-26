// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import '../packet/literal_data.dart';
import 'key.dart';
import 'signature.dart';
import 'verification.dart';

/// Class that represents a cleartext message.
class CleartextMessage {
  /// The cleartext of the message
  final String _text;

  final List<Verification> verifications;

  CleartextMessage(
    final String text, [
    final Iterable<Verification> verifications = const [],
  ])  : _text = text.trimRight().replaceAll(
              RegExp(r'\r?\n', multiLine: true),
              '\r\n',
            ),
        verifications = verifications.toList(growable: false);

  String get text => _text;

  String get normalizeText => _text.replaceAll(
        RegExp(r'\r\n', multiLine: true),
        '\n',
      );

  /// Verify detached signature
  /// Return cleartext message with verifications
  CleartextMessage verifySignature(
    final Signature signature,
    final Iterable<PublicKey> verificationKeys, {
    final DateTime? date,
  }) =>
      CleartextMessage(
        text,
        Verification.createVerifications(
          LiteralDataPacket.fromText(text),
          signature.packets,
          verificationKeys,
          date: date,
        ),
      );
}
