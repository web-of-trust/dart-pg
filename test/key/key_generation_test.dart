import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/ecc.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/enum/key_type.dart';
import 'package:dart_pg/src/enum/key_version.dart';
import 'package:dart_pg/src/enum/rsa_key_size.dart';
import 'package:dart_pg/src/openpgp.dart';
import 'package:test/test.dart';

void main() {
  group('Key generation', () {
    const userID = 'Dart Privacy Guard <dartpg@openpgp.example.com>';
    final passphrase = Helper.generatePassword();

    test('RSA key', () {
      final privateKey = OpenPGP.generateKey(
        [userID],
        passphrase,
        type: KeyType.rsa,
      );
      expect(privateKey.version, KeyVersion.v4.value);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(privateKey.keyStrength, RSAKeySize.high.bits);
      expect(privateKey.users[0].userID, userID);

      final priKey = OpenPGP.readPrivateKey(
        privateKey.armor(),
      ).decrypt(passphrase);
      expect(priKey.fingerprint, privateKey.fingerprint);
      expect(priKey.users[0].userID, userID);
      expect(
        priKey.subkeys[0].fingerprint,
        privateKey.subkeys[0].fingerprint,
      );
    });

    test('ECDSA NIST P-384 key', () {
      final privateKey = OpenPGP.generateKey(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: Ecc.secp384r1,
      );
      final subkey = privateKey.subkeys[0];
      expect(privateKey.version, KeyVersion.v4.value);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.keyStrength, 384);
      expect(privateKey.users[0].userID, userID);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 384);

      final priKey = OpenPGP.readPrivateKey(
        privateKey.armor(),
      ).decrypt(passphrase);
      expect(priKey.fingerprint, privateKey.fingerprint);
      expect(priKey.users[0].userID, userID);
      expect(
        priKey.subkeys[0].fingerprint,
        subkey.fingerprint,
      );
    });

    test('ECDSA Brainpool P-512 key', () {
      final privateKey = OpenPGP.generateKey(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: Ecc.brainpoolP512r1,
      );
      final subkey = privateKey.subkeys[0];
      expect(privateKey.version, KeyVersion.v4.value);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(privateKey.keyStrength, 512);
      expect(privateKey.users[0].userID, userID);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 512);

      final priKey = OpenPGP.readPrivateKey(
        privateKey.armor(),
      ).decrypt(passphrase);
      expect(priKey.fingerprint, privateKey.fingerprint);
      expect(priKey.users[0].userID, userID);
      expect(
        priKey.subkeys[0].fingerprint,
        subkey.fingerprint,
      );
    });

    test('EdDSA legacy key', () {
      final privateKey = OpenPGP.generateKey(
        [userID],
        passphrase,
        type: KeyType.ecc,
        curve: Ecc.ed25519,
      );
      final subkey = privateKey.subkeys[0];
      expect(privateKey.version, KeyVersion.v4.value);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.eddsaLegacy);
      expect(privateKey.keyStrength, 255);
      expect(privateKey.users[0].userID, userID);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 255);

      final priKey = OpenPGP.readPrivateKey(
        privateKey.armor(),
      ).decrypt(passphrase);
      expect(priKey.fingerprint, privateKey.fingerprint);
      expect(priKey.users[0].userID, userID);
      expect(
        priKey.subkeys[0].fingerprint,
        subkey.fingerprint,
      );
    });

    test('RFC9580 Curve 25519 key', () {
      final privateKey = OpenPGP.generateKey(
        [userID],
        passphrase,
        type: KeyType.curve25519,
      );
      final subkey = privateKey.subkeys[0];
      expect(privateKey.version, KeyVersion.v6.value);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ed25519);
      expect(privateKey.keyStrength, 255);
      expect(privateKey.users[0].userID, userID);
      expect(subkey.keyAlgorithm, KeyAlgorithm.x25519);
      expect(subkey.keyStrength, 255);

      final priKey = OpenPGP.readPrivateKey(
        privateKey.armor(),
      ).decrypt(passphrase);
      expect(priKey.fingerprint, privateKey.fingerprint);
      expect(priKey.users[0].userID, userID);
      expect(
        priKey.subkeys[0].fingerprint,
        subkey.fingerprint,
      );
    });

    test('RFC9580 Curve 448 key', () {
      final privateKey = OpenPGP.generateKey(
        [userID],
        passphrase,
        type: KeyType.curve448,
      );
      final subkey = privateKey.subkeys[0];
      expect(privateKey.version, KeyVersion.v6.value);
      expect(privateKey.keyAlgorithm, KeyAlgorithm.ed448);
      expect(privateKey.keyStrength, 448);
      expect(privateKey.users[0].userID, userID);
      expect(subkey.keyAlgorithm, KeyAlgorithm.x448);
      expect(subkey.keyStrength, 448);

      final priKey = OpenPGP.readPrivateKey(
        privateKey.armor(),
      ).decrypt(passphrase);
      expect(priKey.fingerprint, privateKey.fingerprint);
      expect(priKey.users[0].userID, userID);
      expect(
        priKey.subkeys[0].fingerprint,
        subkey.fingerprint,
      );
    });
  });
}
