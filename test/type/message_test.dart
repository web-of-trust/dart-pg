import 'package:dart_pg/src/type/cleartext_message.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/signed_message.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../test_data.dart';

void main() {
  group('Message', () {
    test('sign & verify test', () {
      final signingKey = PrivateKey.fromArmored(privateKey);
      final verificationKey = PublicKey.fromArmored(publicKey);
      final text = faker.randomGenerator.string(100);
      final signedMessage = SignedMessage.signCleartext(text, [signingKey]);
      final verifications = signedMessage.verify([verificationKey]);
      for (var verification in verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);
      }
    });

    test('detached sign & verify test', () {
      final signingKey = PrivateKey.fromArmored(privateKey);
      final verificationKey = PublicKey.fromArmored(publicKey);
      final text = faker.randomGenerator.string(100);
      final signature = SignedMessage.signCleartext(text, [signingKey]).signature;
      final cleartextMessage = CleartextMessage(text);
      final verifications = cleartextMessage.verifyDetached(signature, [verificationKey]);
      for (var verification in verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);
      }
    });
  });
}
