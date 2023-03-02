import 'package:dart_pg/src/type/cleartext_message.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/message.dart';
import 'package:dart_pg/src/type/signed_message.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../test_data.dart';

void main() {
  group('Cleartext message sign & verify', () {
    final signingKey = PrivateKey.fromArmored(privateKey);
    final verificationKey = PublicKey.fromArmored(publicKey);
    final text = faker.randomGenerator.string(1000);

    test('atached test', () {
      final signedMessage = SignedMessage.signCleartext(text, [signingKey]);
      final verifiedMessage = signedMessage.verify([verificationKey]);
      final signature = signedMessage.signature;

      expect(signedMessage.verifications.isEmpty, true);
      expect(verifiedMessage.verifications.isNotEmpty, true);

      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signature.packets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('detached test', () {
      final signature = SignedMessage.signCleartext(text, [signingKey]).signature;
      final cleartextMessage = CleartextMessage(text);
      final verifiedMessage = cleartextMessage.verifySignature(signature, [verificationKey]);

      expect(verifiedMessage.verifications.isNotEmpty, true);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signature.packets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });
  });

  group('Message sign & verify', () {
    final signingKey = PrivateKey.fromArmored(privateKey);
    final verificationKey = PublicKey.fromArmored(publicKey);
    final text = faker.randomGenerator.string(1000);

    test('atached test', () {
      final signedMessage = Message.createTextMessage(text).sign([signingKey]);
      final verifiedMessage = signedMessage.verify([verificationKey]);
      final signaturePackets = signedMessage.signaturePackets;

      expect(signedMessage.signingKeyIDs.elementAt(0).keyID, signingKey.keyID.keyID);
      expect(signedMessage.verifications.isEmpty, true);
      expect(verifiedMessage.verifications.isNotEmpty, true);

      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('detached test', () {
      final message = Message.createTextMessage(text);
      final signature = message.signDetached([signingKey]);
      final verifiedMessage = message.verifySignature(signature, [verificationKey]);

      expect(verifiedMessage.verifications.isNotEmpty, true);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signature.packets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });
  });

  group('Message encryption', () {});
}
