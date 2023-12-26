import 'package:dart_pg/src/enum/curve_info.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/enum/key_generation_type.dart';
import 'package:dart_pg/src/packet/key/key_params.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  group('Read public key', () {
    test('rsa test', () async {
      final publicKey = PublicKey.fromArmored(rsaPublicKey);
      expect(publicKey.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
      expect(publicKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(publicKey.isPrivate, false);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'rsa pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = publicKey.subkeys[0];
      expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
      expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.verify(), isTrue);
    });

    test('dsa elgamal test', () async {
      final publicKey = PublicKey.fromArmored(dsaPublicKey);
      expect(publicKey.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
      expect(publicKey.algorithm, KeyAlgorithm.dsa);
      expect(publicKey.isPrivate, isFalse);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'dsa elgamal pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = publicKey.subkeys[0];
      expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
      expect(subkey.algorithm, KeyAlgorithm.elgamal);
      expect(subkey.verify(), isTrue);
    });

    test('ecc test', () async {
      final publicKey = PublicKey.fromArmored(eccPublicKey);
      expect(publicKey.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
      expect(publicKey.algorithm, KeyAlgorithm.ecdsa);
      expect(publicKey.isPrivate, isFalse);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'ecc pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = publicKey.subkeys[0];
      expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
    });

    test('curve25519 test', () async {
      final publicKey = PublicKey.fromArmored(curve25519PublicKey);
      expect(publicKey.fingerprint, '67287cc6376746e683fd24675654e554d72fcf47');
      expect(publicKey.algorithm, KeyAlgorithm.eddsa);
      expect(publicKey.isPrivate, isFalse);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'curve 25519 pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = publicKey.subkeys[0];
      expect(subkey.fingerprint, '38460d0ea0f3da56ccf63e9d0a4e826effaf48a4');
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
    });
  });

  group('Read private key', () {
    test('rsa test', () async {
      final privateKey =
          PrivateKey.fromArmored(rsaPrivateKey).decrypt(passphrase);
      expect(
          privateKey.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
      expect(privateKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyPacket.isDecrypted, isTrue);
      expect(privateKey.keyPacket.validate(), isTrue);

      final user = privateKey.users[0];
      expect(user.userID!.name, 'rsa pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
      expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.verify(), isTrue);
    });

    test('dsa elgamal test', () async {
      final privateKey =
          PrivateKey.fromArmored(dsaPrivateKey).decrypt(passphrase);
      expect(
          privateKey.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
      expect(privateKey.algorithm, KeyAlgorithm.dsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyPacket.isDecrypted, isTrue);
      expect(privateKey.keyPacket.validate(), isTrue);

      final user = privateKey.users[0];
      expect(user.userID!.name, 'dsa elgamal pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
      expect(subkey.algorithm, KeyAlgorithm.elgamal);
      expect(subkey.verify(), isTrue);
    });

    test('ecc test', () async {
      final privateKey =
          PrivateKey.fromArmored(eccPrivateKey).decrypt(passphrase);
      expect(
          privateKey.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyPacket.isDecrypted, isTrue);
      expect(privateKey.keyPacket.validate(), isTrue);

      final user = privateKey.users[0];
      expect(user.userID!.name, 'ecc pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
    });

    test('curve25519 test', () async {
      final privateKey =
          PrivateKey.fromArmored(curve25519PrivateKey).decrypt(passphrase);
      expect(
          privateKey.fingerprint, '67287cc6376746e683fd24675654e554d72fcf47');
      expect(privateKey.algorithm, KeyAlgorithm.eddsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyPacket.isDecrypted, isTrue);
      expect(privateKey.keyPacket.validate(), isTrue);

      final user = privateKey.users[0];
      expect(user.userID!.name, 'curve 25519 pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.fingerprint, '38460d0ea0f3da56ccf63e9d0a4e826effaf48a4');
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
    });
  });

  group('Generate key', () {
    final name = faker.person.name();
    final email = faker.internet.email().replaceAll("'", '');
    final comment = faker.lorem.words(3).join(' ');
    final userID = [name, '($comment)', '<$email>'].join(' ');
    final passphrase = faker.internet.password();

    test('rsa', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.rsa,
      );
      expect(privateKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 4096);
      expect(privateKey.keyPacket.validate(), isTrue);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.verify(), isTrue);

      final bindingSignature = subkey.bindingSignatures[0];
      expect(bindingSignature.keyFlags!.isEncryptCommunication, isTrue);
      expect(bindingSignature.keyFlags!.isEncryptStorage, isTrue);

      final privateKey2 = privateKey.addSubkey(passphrase);
      final subkey2 = privateKey2.subkeys[1];
      expect(subkey2.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey2.verify(), isTrue);
    });

    test('dsa elGamal', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.dsa,
      );
      expect(privateKey.algorithm, KeyAlgorithm.dsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 2048);
      expect(privateKey.keyPacket.validate(), isTrue);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.elgamal);
      expect(subkey.verify(), isTrue);

      final bindingSignature = subkey.bindingSignatures[0];
      expect(bindingSignature.keyFlags!.isEncryptCommunication, isTrue);
      expect(bindingSignature.keyFlags!.isEncryptStorage, isTrue);

      final privateKey2 = privateKey.addSubkey(passphrase,
          subkeyAlgorithm: KeyAlgorithm.elgamal);
      final subkey2 = privateKey2.subkeys[1];
      expect(subkey2.algorithm, KeyAlgorithm.elgamal);
      expect(subkey2.verify(), isTrue);
    });

    test('prime256v1 curve', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.ecdsa,
        curve: CurveInfo.prime256v1,
      );
      final publicParams =
          privateKey.keyPacket.publicParams as ECDSAPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 256);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.prime256v1);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 256);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.prime256v1);
      expect(subkeyPublicParams.kdfHash, CurveInfo.prime256v1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.prime256v1.symmetricAlgorithm);
    });

    test('secp256k1 curve', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.ecdsa,
        curve: CurveInfo.secp256k1,
      );
      final publicParams =
          privateKey.keyPacket.publicParams as ECDSAPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 256);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.secp256k1);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 256);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.secp256k1);
      expect(subkeyPublicParams.kdfHash, CurveInfo.secp256k1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.secp256k1.symmetricAlgorithm);
    });

    test('secp384r1 curve', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.ecdsa,
        curve: CurveInfo.secp384r1,
      );
      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 384);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.secp384r1);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 384);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.secp384r1);
      expect(subkeyPublicParams.kdfHash, CurveInfo.secp384r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.secp384r1.symmetricAlgorithm);
    });

    test('secp521r1 curve', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.ecdsa,
        curve: CurveInfo.secp521r1,
      );
      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 521);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.secp521r1);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 521);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.secp521r1);
      expect(subkeyPublicParams.kdfHash, CurveInfo.secp521r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.secp521r1.symmetricAlgorithm);
    });

    test('brainpoolp256r1 curve', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.ecdsa,
        curve: CurveInfo.brainpoolP256r1,
      );
      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 256);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.brainpoolP256r1);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 256);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.brainpoolP256r1);
      expect(
          subkeyPublicParams.kdfHash, CurveInfo.brainpoolP256r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.brainpoolP256r1.symmetricAlgorithm);
    });

    test('brainpoolp384r1 curve', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.ecdsa,
        curve: CurveInfo.brainpoolP384r1,
      );
      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 384);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.brainpoolP384r1);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 384);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.brainpoolP384r1);
      expect(
          subkeyPublicParams.kdfHash, CurveInfo.brainpoolP384r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.brainpoolP384r1.symmetricAlgorithm);
    });

    test('brainpoolp512r1 curve', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.ecdsa,
        curve: CurveInfo.brainpoolP512r1,
      );
      final publicParams = privateKey.keyPacket.publicParams as ECPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 512);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.brainpoolP512r1);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 512);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.brainpoolP512r1);
      expect(
          subkeyPublicParams.kdfHash, CurveInfo.brainpoolP512r1.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.brainpoolP512r1.symmetricAlgorithm);

      final privateKey2 = privateKey.addSubkey(passphrase,
          subkeyAlgorithm: KeyAlgorithm.ecdh, curve: CurveInfo.secp521r1);

      final subkey2 = privateKey2.subkeys[1];
      expect(subkey2.algorithm, KeyAlgorithm.ecdh);
      expect(subkey2.verify(), isTrue);

      final publicParams2 = subkey2.publicParams as ECDHPublicParams;
      expect(publicParams2.curve, CurveInfo.secp521r1);
    });

    test('curve25519', () async {
      final privateKey = PrivateKey.generate(
        [userID],
        passphrase,
        type: KeyGenerationType.eddsa,
      );
      final publicParams =
          privateKey.keyPacket.publicParams as EdDSAPublicParams;
      expect(privateKey.algorithm, KeyAlgorithm.eddsa);
      expect(privateKey.isPrivate, isTrue);
      expect(privateKey.keyStrength, 255);
      expect(privateKey.keyPacket.validate(), isTrue);
      expect(publicParams.curve, CurveInfo.ed25519);

      final user = privateKey.users[0];
      expect(user.userID!.name, name);
      expect(user.userID!.email, email);
      expect(user.userID!.comment, comment);
      expect(user.verify(), isTrue);

      final subkey = privateKey.subkeys[0];
      expect(subkey.algorithm, KeyAlgorithm.ecdh);
      expect(subkey.verify(), isTrue);
      expect(subkey.keyStrength, 255);

      final subkeyPublicParams =
          subkey.keyPacket.publicParams as ECDHPublicParams;
      expect(subkeyPublicParams.curve, CurveInfo.curve25519);
      expect(subkeyPublicParams.kdfHash, CurveInfo.curve25519.hashAlgorithm);
      expect(subkeyPublicParams.kdfSymmetric,
          CurveInfo.curve25519.symmetricAlgorithm);

      final privateKey2 = privateKey.addSubkey(passphrase,
          subkeyAlgorithm: KeyAlgorithm.ecdh, curve: CurveInfo.curve25519);
      final subkey2 = privateKey2.subkeys[1];
      expect(subkey2.algorithm, KeyAlgorithm.ecdh);
      expect(subkey2.verify(), isTrue);

      final publicParams2 = subkey2.publicParams as ECDHPublicParams;
      expect(publicParams2.curve, CurveInfo.curve25519);
    });
  });
}
