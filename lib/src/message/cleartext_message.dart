/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../common/helpers.dart';
import '../message/signature.dart';
import '../message/signed_message.dart';
import '../packet/base_packet.dart';
import '../type/cleartext_message.dart';
import '../type/key.dart';
import '../type/notation_data.dart';
import '../type/signature.dart';

/// Cleartext message class that represents an OpenPGP cleartext message.
/// See RFC 9580, section 7.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class CleartextMessage implements CleartextMessageInterface {
  @override
  final String text;

  CleartextMessage(this.text);

  @override
  String get normalizeText => text.removeTrailingSpaces().replaceAll(
        RegExp(r'\r?\n', multiLine: true),
        '\r\n',
      );

  @override
  sign(
    Iterable<PrivateKeyInterface> signingKeys, {
    Iterable<KeyInterface> recipients = const [],
    NotationDataInterface? notationData,
    DateTime? time,
  }) {
    return SignedMessage(
        text,
        signDetached(
          signingKeys,
          recipients: recipients,
          notationData: notationData,
          time: time,
        ));
  }

  @override
  signDetached(
    Iterable<PrivateKeyInterface> signingKeys, {
    Iterable<KeyInterface> recipients = const [],
    NotationDataInterface? notationData,
    DateTime? time,
  }) {
    if (signingKeys.isEmpty) {
      throw ArgumentError('No signing keys provided.');
    }
    return Signature(signingKeys.map((signKey) {
      return SignaturePacket.createLiteralData(
        signKey.secretKeyPacket,
        LiteralDataPacket.fromText(text),
        recipients: recipients,
        notationData: notationData,
        time: time,
      );
    }));
  }

  @override
  verifyDetached(
    Iterable<KeyInterface> verificationKeys,
    SignatureInterface signature, [
    DateTime? time,
  ]) {
    return signature.verifyCleartext(
      verificationKeys,
      this,
      time,
    );
  }
}
