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
      final kp1 = keyGen.generateKeyPair();
      final kp2 = keyGen.generateKeyPair();

      final e1 = ECDHBasicAgreement()..init(kp1.privateKey as ECPrivateKey);
      final e2 = ECDHBasicAgreement()..init(kp2.privateKey as ECPrivateKey);

      final sk1 = e1.calculateAgreement(kp2.publicKey as ECPublicKey);
      final sk2 = e2.calculateAgreement(kp1.publicKey as ECPublicKey);
      expect(sk1.compareTo(sk2), 0, reason: 'calculated agreement test failed');
    });
  });
}
