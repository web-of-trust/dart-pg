import 'package:dart_pg/src/type/cleartext_message.dart';
import 'package:dart_pg/src/type/key.dart';
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
      for (var verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);
      }
    });

    test('detached test', () {
      final signature = SignedMessage.signCleartext(text, [signingKey]).signature;
      final cleartextMessage = CleartextMessage(text);
      final verifiedMessage = cleartextMessage.verifySignature(signature, [verificationKey]);
      for (var verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);
      }
    });
  });
}
