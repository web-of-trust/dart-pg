import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/openpgp.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  group('Key decryption', () {
    const userID = 'Dart Privacy Guard <dartpg@openpgp.example.com>';
    const passphrase = 'password';

    test('RSA key', () {
      final privateKey = OpenPGP.decryptPrivateKey(
        lockedRsaPrivateKey,
        passphrase,
      );
      final user = privateKey.users[0];
      final subkey = privateKey.subkeys[0];

      expect(
        privateKey.fingerprint.toHexadecimal(),
        '5ccceda54f917089f8c488000532372a028f2ff5',
      );
      expect(privateKey.version, 4);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(privateKey.keyStrength, 2048);

      expect(
        subkey.fingerprint.toHexadecimal(),
        '79fb82ac1204bdc854e87364316ef1539787254f',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.keyStrength, 2048);

      expect(user.userID, userID);

      final encrypted = OpenPGP.encryptPrivateKey(
        privateKey,
        Helper.generatePassword(),
      );
      expect(
        privateKey.fingerprint.toHexadecimal(),
        encrypted.fingerprint.toHexadecimal(),
      );
    });

    test('DSA & ElGamal key', () {
      final privateKey = OpenPGP.decryptPrivateKey(
        lockDsaElGamalPrivateKey,
        passphrase,
      );
      final user = privateKey.users[0];
      final subkey = privateKey.subkeys[0];

      expect(
        privateKey.fingerprint.toHexadecimal(),
        '9a83344a3711864c1f502094ba727d0f6b50c281',
      );
      expect(privateKey.version, 4);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.dsa);
      expect(privateKey.keyStrength, 2048);

      expect(
        subkey.fingerprint.toHexadecimal(),
        '8f1cb653b2c3a4808302b63b52c1ed36e9e22006',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.elgamal);
      expect(subkey.keyStrength, 2048);

      expect(user.userID, userID);

      final encrypted = OpenPGP.encryptPrivateKey(
        privateKey,
        Helper.generatePassword(),
      );
      expect(
        privateKey.fingerprint.toHexadecimal(),
        encrypted.fingerprint.toHexadecimal(),
      );
    });

    test('ECC NIST P-384 key', () {
      final privateKey = OpenPGP.decryptPrivateKey(
        lockedEccNistP384PrivateKey,
        passphrase,
      );
      final user = privateKey.users[0];
      final subkey = privateKey.subkeys[0];

      expect(
        privateKey.fingerprint.toHexadecimal(),
        'a325107e66bcab3eea407550396ecb8bb86d1922',
      );
      expect(privateKey.version, 4);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.keyStrength, 384);

      expect(
        subkey.fingerprint.toHexadecimal(),
        'bd7133409a3ad7986fbae32a5a2990ce6bd63b20',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 384);

      expect(user.userID, userID);

      final encrypted = OpenPGP.encryptPrivateKey(
        privateKey,
        Helper.generatePassword(),
      );
      expect(
        privateKey.fingerprint.toHexadecimal(),
        encrypted.fingerprint.toHexadecimal(),
      );
    });

    test('ECC Brainpool P-256 key', () {
      final privateKey = OpenPGP.decryptPrivateKey(
        lockedEccBrainpoolP256PrivateKey,
        passphrase,
      );
      final user = privateKey.users[0];
      final subkey = privateKey.subkeys[0];

      expect(
        privateKey.fingerprint.toHexadecimal(),
        'cd1b5b14294f80be65cefbef9951219fc9de9578',
      );
      expect(privateKey.version, 4);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.keyStrength, 256);

      expect(
        subkey.fingerprint.toHexadecimal(),
        'fda27358dac2b11fb5388cca65b53bd1aff05e06',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 256);

      expect(user.userID, userID);

      final encrypted = OpenPGP.encryptPrivateKey(
        privateKey,
        Helper.generatePassword(),
      );
      expect(
        privateKey.fingerprint.toHexadecimal(),
        encrypted.fingerprint.toHexadecimal(),
      );
    });

    test('ECC Curve 25519 key', () {
      final privateKey = OpenPGP.decryptPrivateKey(
        lockedEccCurve25519PrivateKey,
        passphrase,
      );
      final user = privateKey.users[0];
      final subkey = privateKey.subkeys[0];

      expect(
        privateKey.fingerprint.toHexadecimal(),
        '1148b2a24f580977c27b26223ed475dd212d221e',
      );
      expect(privateKey.version, 4);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.eddsaLegacy);
      expect(privateKey.keyStrength, 255);

      expect(
        subkey.fingerprint.toHexadecimal(),
        '12ba12e01b12582680057e8b44d20d3a674af1a7',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 255);

      expect(user.userID, userID);

      final encrypted = OpenPGP.encryptPrivateKey(
        privateKey,
        Helper.generatePassword(),
      );
      expect(
        privateKey.fingerprint.toHexadecimal(),
        encrypted.fingerprint.toHexadecimal(),
      );
    });

    test('Rfc9580 Curve 25519 key', () {
      final privateKey = OpenPGP.decryptPrivateKey(
        lockRfc9580Curve25519PrivateKey,
        passphrase,
      );
      final directSignature = privateKey.directSignatures[0];
      final user = privateKey.users[0];
      final subkey = privateKey.subkeys[0];

      expect(
        privateKey.fingerprint.toHexadecimal(),
        '960c463bb00a3a66a25afb8b6cc291d81520834853f325d10962f71a8b44a34c',
      );
      expect(
        directSignature.issuerFingerprint.toHexadecimal(),
        '960c463bb00a3a66a25afb8b6cc291d81520834853f325d10962f71a8b44a34c',
      );
      expect(privateKey.version, 6);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ed25519);
      expect(privateKey.keyStrength, 255);

      expect(
        subkey.fingerprint.toHexadecimal(),
        'd06da2dc36880041a63e014afa1907e04112d44fb11c0918158a5a2a6e988193',
      );
      expect(subkey.version, 6);
      expect(subkey.keyAlgorithm, KeyAlgorithm.x25519);
      expect(subkey.keyStrength, 255);

      expect(user.userID, userID);

      final encrypted = OpenPGP.encryptPrivateKey(
        privateKey,
        Helper.generatePassword(),
      );
      expect(
        privateKey.fingerprint.toHexadecimal(),
        encrypted.fingerprint.toHexadecimal(),
      );
    });

    test('Rfc9580 Curve 448 key', () {
      final privateKey = OpenPGP.decryptPrivateKey(
        lockedRfc9580Curve448PrivateKey,
        passphrase,
      );
      final directSignature = privateKey.directSignatures[0];
      final user = privateKey.users[0];
      final subkey = privateKey.subkeys[0];

      expect(
        privateKey.fingerprint.toHexadecimal(),
        '5c1974b80400bc2e2f873e8e5eae923bb6d40b44346fa94cd9fd83190a621258',
      );
      expect(
        directSignature.issuerFingerprint.toHexadecimal(),
        '5c1974b80400bc2e2f873e8e5eae923bb6d40b44346fa94cd9fd83190a621258',
      );
      expect(privateKey.version, 6);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ed448);
      expect(privateKey.keyStrength, 448);

      expect(
        subkey.fingerprint.toHexadecimal(),
        'a831a2141587c8bace0971316b2f15a5be482ddf3b059d3b8589d989ee740693',
      );
      expect(subkey.version, 6);
      expect(subkey.keyAlgorithm, KeyAlgorithm.x448);
      expect(subkey.keyStrength, 448);

      expect(user.userID, userID);

      final encrypted = OpenPGP.encryptPrivateKey(
        privateKey,
        Helper.generatePassword(),
      );
      expect(
        privateKey.fingerprint.toHexadecimal(),
        encrypted.fingerprint.toHexadecimal(),
      );
    });
  });
}
