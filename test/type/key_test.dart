import 'package:dart_pg/src/enum/curve_info.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/enum/key_type.dart';
import 'package:dart_pg/src/packet/key/key_params.dart';
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
    final email = faker.internet.email().replaceAll("'", '');
    final comment = faker.lorem.words(3).join(' ');
    final userID = [name, '($comment)', '<$email>'].join(' ');
    final passphrase = faker.internet.password();

    test('rsa', () {
      final privateKey = PrivateKey.generate(
        [userID],
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

      final bindingSignature = subkey.bindingSignatures[0];
      expect(bindingSignature.keyFlags!.isEncryptCommunication, isTrue);
      expect(bindingSignature.keyFlags!.isEncryptStorage, isTrue);

      expect(
        () => PrivateKey.generate(
          [userID],
          passphrase,
          type: KeyType.rsa,
          rsaBits: 1024,
        ),
        throwsArgumentError,
      );
    });

    test('prime256v1 curve', () {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: CurveInfo.prime256v1,
      );

      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 256);

      final publicParams = privateKey.keyPacket.publicParams as ECDSAPublicParams;
      final secretParams = privateKey.keyPacket.secretParams as ECSecretParams;
      expect(publicParams.oid.objectIdentifierAsString, CurveInfo.prime256v1.identifierString);
      expect(publicParams.publicKey.Q, publicParams.publicKey.parameters!.G * secretParams.d);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
      expect(subkey.keyStrength, 256);

      final subkeyPublicParams = subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.oid.objectIdentifierAsString, CurveInfo.prime256v1.identifierString);
      expect(subkeyPublicParams.kdfHash, CurveInfo.prime256v1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric, CurveInfo.prime256v1.symmetricAlgorithm);
    });

    test('secp256k1 curve', () {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: CurveInfo.secp256k1,
      );

      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 256);

      final publicParams = privateKey.keyPacket.publicParams as ECDSAPublicParams;
      final secretParams = privateKey.keyPacket.secretParams as ECSecretParams;
      expect(publicParams.oid.objectIdentifierAsString, CurveInfo.secp256k1.identifierString);
      expect(publicParams.publicKey.Q, publicParams.publicKey.parameters!.G * secretParams.d);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
      expect(subkey.keyStrength, 256);

      final subkeyPublicParams = subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.oid.objectIdentifierAsString, CurveInfo.secp256k1.identifierString);
      expect(subkeyPublicParams.kdfHash, CurveInfo.secp256k1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric, CurveInfo.secp256k1.symmetricAlgorithm);
    });

    test('secp384r1 curve', () {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: CurveInfo.secp384r1,
      );

      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 384);

      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(publicParams.oid.objectIdentifierAsString, CurveInfo.secp384r1.identifierString);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
      expect(subkey.keyStrength, 384);

      final subkeyPublicParams = subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.oid.objectIdentifierAsString, CurveInfo.secp384r1.identifierString);
      expect(subkeyPublicParams.kdfHash, CurveInfo.secp384r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric, CurveInfo.secp384r1.symmetricAlgorithm);
    });

    test('secp521r1 curve', () {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: CurveInfo.secp521r1,
      );

      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 521);

      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(publicParams.oid.objectIdentifierAsString, CurveInfo.secp521r1.identifierString);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
      expect(subkey.keyStrength, 521);

      final subkeyPublicParams = subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.oid.objectIdentifierAsString, CurveInfo.secp521r1.identifierString);
      expect(subkeyPublicParams.kdfHash, CurveInfo.secp521r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric, CurveInfo.secp521r1.symmetricAlgorithm);
    });

    test('brainpoolp256r1 curve', () {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: CurveInfo.brainpoolp256r1,
      );

      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 256);

      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(publicParams.oid.objectIdentifierAsString, CurveInfo.brainpoolp256r1.identifierString);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
      expect(subkey.keyStrength, 256);

      final subkeyPublicParams = subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.oid.objectIdentifierAsString, CurveInfo.brainpoolp256r1.identifierString);
      expect(subkeyPublicParams.kdfHash, CurveInfo.brainpoolp256r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric, CurveInfo.brainpoolp256r1.symmetricAlgorithm);
    });

    test('brainpoolp384r1 curve', () {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: CurveInfo.brainpoolp384r1,
      );

      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 384);

      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(publicParams.oid.objectIdentifierAsString, CurveInfo.brainpoolp384r1.identifierString);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
      expect(subkey.keyStrength, 384);

      final subkeyPublicParams = subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.oid.objectIdentifierAsString, CurveInfo.brainpoolp384r1.identifierString);
      expect(subkeyPublicParams.kdfHash, CurveInfo.brainpoolp384r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric, CurveInfo.brainpoolp384r1.symmetricAlgorithm);
    });

    test('brainpoolp512r1 curve', () {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: CurveInfo.brainpoolp512r1,
      );

      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, true);
      expect(privateKey.keyStrength, 512);

      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(publicParams.oid.objectIdentifierAsString, CurveInfo.brainpoolp512r1.identifierString);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(privateKey.keyPacket), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(privateKey.keyPacket), isTrue);
      expect(subkey.keyStrength, 512);

      final subkeyPublicParams = subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.oid.objectIdentifierAsString, CurveInfo.brainpoolp512r1.identifierString);
      expect(subkeyPublicParams.kdfHash, CurveInfo.brainpoolp512r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric, CurveInfo.brainpoolp512r1.symmetricAlgorithm);
    });

    test('curve25519', () {
      expect(
        () => PrivateKey.generate(
          [userID],
          passphrase,
          type: KeyType.ecc,
          curve: CurveInfo.curve25519,
        ),
        throwsUnsupportedError,
      );
      expect(
        () => PrivateKey.generate(
          [userID],
          passphrase,
          type: KeyType.ecc,
          curve: CurveInfo.ed25519,
        ),
        throwsUnsupportedError,
      );
    });
  });
}
