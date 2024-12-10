import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/openpgp.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  group('Key reading', () {
    const userID = 'Dart Privacy Guard <dartpg@openpgp.example.com>';

    test('RSA key', () {
      final publicKey = OpenPGP.readPublicKey(rsaPublickey);
      final user = publicKey.users[0];
      final subkey = publicKey.subkeys[0];

      expect(
        publicKey.fingerprint.toHexadecimal(),
        '5ccceda54f917089f8c488000532372a028f2ff5',
      );
      expect(publicKey.version, 4);
      expect(publicKey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(publicKey.keyStrength, 2048);

      expect(
        subkey.fingerprint.toHexadecimal(),
        '79fb82ac1204bdc854e87364316ef1539787254f',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(subkey.keyStrength, 2048);

      expect(user.userID, userID);
    });

    test('DSA & ElGamal key', () {
      final publicKey = OpenPGP.readPublicKey(dsaElGamalPublicKey);
      final user = publicKey.users[0];
      final subkey = publicKey.subkeys[0];

      expect(
        publicKey.fingerprint.toHexadecimal(),
        '9a83344a3711864c1f502094ba727d0f6b50c281',
      );
      expect(publicKey.version, 4);
      expect(publicKey.keyAlgorithm, KeyAlgorithm.dsa);
      expect(publicKey.keyStrength, 2048);

      expect(
        subkey.fingerprint.toHexadecimal(),
        '8f1cb653b2c3a4808302b63b52c1ed36e9e22006',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.elgamal);
      expect(subkey.keyStrength, 2048);

      expect(user.userID, userID);
    });

    test('ECC NIST P-384 key', () {
      final publicKey = OpenPGP.readPublicKey(eccNistP384PublicKey);
      final user = publicKey.users[0];
      final subkey = publicKey.subkeys[0];

      expect(
        publicKey.fingerprint.toHexadecimal(),
        'a325107e66bcab3eea407550396ecb8bb86d1922',
      );
      expect(publicKey.version, 4);
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(publicKey.keyStrength, 384);

      expect(
        subkey.fingerprint.toHexadecimal(),
        'bd7133409a3ad7986fbae32a5a2990ce6bd63b20',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 384);

      expect(user.userID, userID);
    });

    test('ECC Brainpool P-256 key', () {
      final publicKey = OpenPGP.readPublicKey(eccBrainpoolP256PublicKey);
      final user = publicKey.users[0];
      final subkey = publicKey.subkeys[0];

      expect(
        publicKey.fingerprint.toHexadecimal(),
        'cd1b5b14294f80be65cefbef9951219fc9de9578',
      );
      expect(publicKey.version, 4);
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(publicKey.keyStrength, 256);

      expect(
        subkey.fingerprint.toHexadecimal(),
        'fda27358dac2b11fb5388cca65b53bd1aff05e06',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 256);

      expect(user.userID, userID);
    });

    test('ECC Curve 25519 key', () {
      final publicKey = OpenPGP.readPublicKey(eccCurve25519PublicKey);
      final user = publicKey.users[0];
      final subkey = publicKey.subkeys[0];

      expect(
        publicKey.fingerprint.toHexadecimal(),
        '1148b2a24f580977c27b26223ed475dd212d221e',
      );
      expect(publicKey.version, 4);
      expect(publicKey.keyAlgorithm, KeyAlgorithm.eddsaLegacy);
      expect(publicKey.keyStrength, 255);

      expect(
        subkey.fingerprint.toHexadecimal(),
        '12ba12e01b12582680057e8b44d20d3a674af1a7',
      );
      expect(subkey.version, 4);
      expect(subkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(subkey.keyStrength, 255);

      expect(user.userID, userID);
    });

    test('Rfc9580 Curve 25519 key', () {
      final publicKey = OpenPGP.readPublicKey(rfc9580Curve25519PublicKey);
      final directSignature = publicKey.directSignatures[0];
      final user = publicKey.users[0];
      final subkey = publicKey.subkeys[0];

      expect(
        publicKey.fingerprint.toHexadecimal(),
        '7b2522d17acbc689154050fb1a2455f9fc9a46318ad6ef5039d3e6e3bc04a679',
      );
      expect(
        directSignature.issuerFingerprint.toHexadecimal(),
        '7b2522d17acbc689154050fb1a2455f9fc9a46318ad6ef5039d3e6e3bc04a679',
      );
      expect(publicKey.version, 6);
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ed25519);
      expect(publicKey.keyStrength, 255);

      expect(
        subkey.fingerprint.toHexadecimal(),
        'ef330d173def1188f84a0904394ae44b89ae2e9413e33ac524602beec62a13b0',
      );
      expect(subkey.version, 6);
      expect(subkey.keyAlgorithm, KeyAlgorithm.x25519);
      expect(subkey.keyStrength, 255);

      expect(user.userID, userID);
    });

    test('Rfc9580 Curve 448 key', () {
      final publicKey = OpenPGP.readPublicKey(rfc9580Curve448PublicKey);
      final directSignature = publicKey.directSignatures[0];
      final user = publicKey.users[0];
      final subkey = publicKey.subkeys[0];

      expect(
        publicKey.fingerprint.toHexadecimal(),
        '93877c2a7656e41e8e39a16d405614663a4c5593da3306f78035f466669c6051',
      );
      expect(
        directSignature.issuerFingerprint.toHexadecimal(),
        '93877c2a7656e41e8e39a16d405614663a4c5593da3306f78035f466669c6051',
      );
      expect(publicKey.version, 6);
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ed448);
      expect(publicKey.keyStrength, 448);

      expect(
        subkey.fingerprint.toHexadecimal(),
        '21a08e3d6074094d6978ba062176baa279dbf992577f806e13696d7252775b68',
      );
      expect(subkey.version, 6);
      expect(subkey.keyAlgorithm, KeyAlgorithm.x448);
      expect(subkey.keyStrength, 448);

      expect(user.userID, userID);
    });

    test('Multiple public keys', () {
      final publicKeys = OpenPGP.readPublicKeys(multiplePublicKeys).toList();
      expect(publicKeys.length, 5);
      expect(
        publicKeys[0].fingerprint.toHexadecimal(),
        '5ccceda54f917089f8c488000532372a028f2ff5',
      );
      expect(
        publicKeys[1].fingerprint.toHexadecimal(),
        '9a83344a3711864c1f502094ba727d0f6b50c281',
      );
      expect(
        publicKeys[2].fingerprint.toHexadecimal(),
        'a325107e66bcab3eea407550396ecb8bb86d1922',
      );
      expect(
        publicKeys[3].fingerprint.toHexadecimal(),
        'cd1b5b14294f80be65cefbef9951219fc9de9578',
      );
      expect(
        publicKeys[4].fingerprint.toHexadecimal(),
        '1148b2a24f580977c27b26223ed475dd212d221e',
      );

      final armor = Armor.decode(OpenPGP.armorPublicKeys(publicKeys));
      expect(armor.type, ArmorType.publicKey);
    });
  });
}
