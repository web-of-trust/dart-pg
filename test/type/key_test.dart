import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../test_data.dart';

void main() {
  group('Read public key', () {
    test('rsa test', () {
      final publicKey = PublicKey.fromArmored(rsaPublicKey);
      expect(publicKey.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
      expect(publicKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(publicKey.isPrivate, false);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'rsa pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(publicKey.keyPacket), isTrue);

      final subkey = publicKey.subkeys[0];
      expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
      expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.verify(publicKey.keyPacket), isTrue);
    });

    test('dsa elgamal test', () {
      final publicKey = PublicKey.fromArmored(dsaPublicKey);
      expect(publicKey.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
      expect(publicKey.algorithm, KeyAlgorithm.dsa);
      expect(publicKey.isPrivate, false);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'dsa elgamal pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(publicKey.keyPacket), isTrue);

      final subkey = publicKey.subkeys[0];
      expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
      expect(subkey.algorithm, KeyAlgorithm.elgamal);
      expect(subkey.verify(publicKey.keyPacket), isTrue);
    });

    test('ecc test', () {
      final publicKey = PublicKey.fromArmored(eccPublicKey);
      expect(publicKey.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
      expect(publicKey.algorithm, KeyAlgorithm.ecdsa);
      expect(publicKey.isPrivate, false);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'ecc pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(publicKey.keyPacket), isTrue);

      final subkey = publicKey.subkeys[0];
      expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(publicKey.keyPacket), isTrue);
    });
  });

  group('Read private key', () {
    test('rsa test', () {
      final privateKey = PrivateKey.fromArmored(rsaPrivateKey).decrypt(passphrase);
      expect(privateKey.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
      expect(privateKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyPacket.isDecrypted, true);

      final user = privateKey.users[0];
      expect(user.userID!.name, 'rsa pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
      expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
    });

    test('dsa elgamal test', () {
      final privateKey = PrivateKey.fromArmored(dsaPrivateKey).decrypt(passphrase);
      expect(privateKey.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
      expect(privateKey.algorithm, KeyAlgorithm.dsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyPacket.isDecrypted, true);

      final user = privateKey.users[0];
      expect(user.userID!.name, 'dsa elgamal pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
      expect(subkey.algorithm, KeyAlgorithm.elgamal);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
    });

    test('ecc test', () {
      final privateKey = PrivateKey.fromArmored(eccPrivateKey).decrypt(passphrase);
      expect(privateKey.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyPacket.isDecrypted, true);

      final user = privateKey.users[0];
      expect(user.userID!.name, 'ecc pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
    });
  });

  group('Generate key', () {
    final name = faker.person.name();
    final email = faker.internet.email();
    final comment = faker.lorem.words(3).join(' ');
    final passphrase = faker.internet.password();

    test('rsa', () {
      final privateKey = PrivateKey.generate(
        [
          [name, '($comment)', '<$email>'].join(' ')
        ],
        passphrase,
        type: KeyType.rsa,
      );
      expect(privateKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 4096);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
    });
  });
}
