import 'package:dart_pg/src/crypto/ecc/curve25519.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:test/test.dart';

void main() {
  group('curve25519', () {
    test('key generator & agreement', () {
      final keyGen = KeyGenerator('EC')
        ..init(
          ParametersWithRandom(
            ECKeyGeneratorParameters(Curve25519DomainParameters()),
            Helper.secureRandom(),
          ),
        );
      final bobKP = keyGen.generateKeyPair();
      final aliceKP = keyGen.generateKeyPair();

      final bobKA = ECDHBasicAgreement()..init(bobKP.privateKey as ECPrivateKey);
      final aliceKA = ECDHBasicAgreement()..init(aliceKP.privateKey as ECPrivateKey);

      final aliceShared = bobKA.calculateAgreement(aliceKP.publicKey as ECPublicKey);
      final bobShared = aliceKA.calculateAgreement(bobKP.publicKey as ECPublicKey);
      expect(aliceShared, bobShared, reason: 'Failed asserting that Alice and Bob share the same BigInteger.');
    });
  });
}
