import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/src/armor/armor.dart';
import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/key/dsa_public_params.dart';
import 'package:dart_pg/src/key/dsa_secret_params.dart';
import 'package:dart_pg/src/key/ec_secret_params.dart';
import 'package:dart_pg/src/key/ecdh_public_params.dart';
import 'package:dart_pg/src/key/ecdsa_public_params.dart';
import 'package:dart_pg/src/key/elgamal_public_params.dart';
import 'package:dart_pg/src/key/elgamal_secret_params.dart';
import 'package:dart_pg/src/key/rsa_public_params.dart';
import 'package:dart_pg/src/key/rsa_secret_params.dart';
import 'package:dart_pg/src/packet/image_attribute.dart';
import 'package:dart_pg/src/packet/packet_list.dart';
import 'package:dart_pg/src/packet/public_key.dart';
import 'package:dart_pg/src/packet/public_subkey.dart';
import 'package:dart_pg/src/packet/secret_key.dart';
import 'package:dart_pg/src/packet/secret_subkey.dart';
import 'package:dart_pg/src/packet/user_attribute.dart';
import 'package:dart_pg/src/packet/user_attribute_subpacket.dart';
import 'package:dart_pg/src/packet/user_id.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import 'test_data.dart';

void main() {
  group('user packet tests', (() {
    final faker = Faker();
    test('user id test', (() {
      final name = faker.person.name();
      final email = faker.internet.email();
      final comment = faker.lorem.words(3).join(' ');

      final userId = UserIDPacket(name, email, comment: comment);
      expect(userId.name, name);
      expect(userId.email, email);
      expect(userId.comment, comment);

      final cloneUserId = UserIDPacket.fromPacketData(userId.toPacketData());
      expect(userId.name, cloneUserId.name);
      expect(userId.email, cloneUserId.email);
      expect(userId.comment, cloneUserId.comment);
    }));

    test('user attribute test', (() {
      final imageData = Uint8List.fromList(faker.randomGenerator.numbers(255, 100));
      final subpacketType = faker.randomGenerator.integer(100);
      final subpacketData = utf8.encoder.convert(faker.lorem.words(100).join(' '));

      final userAttr = UserAttributePacket.fromPacketData(UserAttributePacket([
        ImageAttributeSubpacket.fromImageData(imageData),
        UserAttributeSubpacket(subpacketType, subpacketData),
      ]).toPacketData());
      final imageAttr = userAttr.attributes[0] as ImageAttributeSubpacket;
      final subpacket = userAttr.attributes[1];

      expect(imageAttr.version, 0x01);
      expect(imageAttr.encoding, ImageAttributeSubpacket.jpeg);
      expect(imageAttr.imageData, imageData);

      expect(subpacket.type, subpacketType);
      expect(subpacket.data, subpacketData);
    }));
  }));

  group('public key packet tests', () {
    test('rsa test', () {
      final deArmor = Armor.decode(rsaPublicKey);
      expect(deArmor['type'], ArmorType.publicKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.publicKey) {
          final key = packet as PublicKeyPacket;
          expect(key.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
          expect(key.algorithm, KeyAlgorithm.rsaEncryptSign);
        }
        if (packet.tag == PacketTag.publicSubkey) {
          final subkey = packet as PublicSubkeyPacket;
          expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
          expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
        }
      }
    });

    test('dsa elgamal test', () {
      final deArmor = Armor.decode(dsaPublicKey);
      expect(deArmor['type'], ArmorType.publicKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.publicKey) {
          final key = packet as PublicKeyPacket;
          expect(key.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
          expect(key.algorithm, KeyAlgorithm.dsa);
        }
        if (packet.tag == PacketTag.publicSubkey) {
          final subkey = packet as PublicSubkeyPacket;
          expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
          expect(subkey.algorithm, KeyAlgorithm.elgamal);
        }
      }
    });

    test('ecc test', () {
      final deArmor = Armor.decode(eccPublicKey);
      expect(deArmor['type'], ArmorType.publicKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.publicKey) {
          final key = packet as PublicKeyPacket;
          expect(key.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
          expect(key.algorithm, KeyAlgorithm.ecdsa);
        }
        if (packet.tag == PacketTag.publicSubkey) {
          final subkey = packet as PublicSubkeyPacket;
          expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
          expect(subkey.algorithm, KeyAlgorithm.ecdh);
        }
      }
    });
  });

  group('secret key packet tests', () {
    test('rsa test', (() {
      final deArmor = Armor.decode(rsaPrivateKey);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as RSAPublicParams;
          final secretParams = key.decrypt(passphrase) as RSASecretParams;

          expect(key.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
          expect(key.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP!.modInverse(secretParams.primeQ!));
          expect(publicParams.modulus, secretParams.modulus);
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as RSAPublicParams;
          final secretParams = subkey.decrypt(passphrase) as RSASecretParams;

          expect(subkey.fingerprint, '8da510f6630e613b4e4b627a1500062542172d9c');
          expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP!.modInverse(secretParams.primeQ!));
          expect(publicParams.modulus, secretParams.modulus);
        }
      }
    }));

    test('dsa elgamal test', () {
      final deArmor = Armor.decode(dsaPrivateKey);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as DSAPublicParams;
          final secretParams = key.decrypt(passphrase) as DSASecretParams;

          expect(key.fingerprint, 'd7143f20460ecd568e1ed6cd76c0caec8769a8a7');
          expect(key.algorithm, KeyAlgorithm.dsa);
          expect(publicParams.publicExponent,
              publicParams.groupGenerator.modPow(secretParams.secretExponent, publicParams.primeP));
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as ElGamalPublicParams;
          final secretParams = subkey.decrypt(passphrase) as ElGamalSecretParams;

          expect(subkey.fingerprint, 'cabe81ea1ab72a92e1c0c65c16e7d1ac9c6620c8');
          expect(subkey.algorithm, KeyAlgorithm.elgamal);
          expect(publicParams.publicExponent,
              publicParams.groupGenerator.modPow(secretParams.secretExponent, publicParams.primeP));
        }
      }
    });

    test('ecc test', () {
      final deArmor = Armor.decode(eccPrivateKey);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as ECDsaPublicParams;
          final secretParams = key.decrypt(passphrase) as ECSecretParams;

          expect(key.fingerprint, '2d84ae177c1bed087cb9903cdeefcc766e22aedf');
          expect(key.algorithm, KeyAlgorithm.ecdsa);
          expect(publicParams.publicKey.Q, publicParams.publicKey.parameters!.G * secretParams.d);
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as ECDHPublicParams;
          final secretParams = subkey.decrypt(passphrase) as ECSecretParams;

          expect(subkey.fingerprint, '7a2da9aa8c176411d6ed1d2f24373aaf7d84b6be');
          expect(subkey.algorithm, KeyAlgorithm.ecdh);
          expect(publicParams.publicKey.Q, publicParams.publicKey.parameters!.G * secretParams.d);
        }
      }
    });

    test('rsa without passphase test', (() {
      final rsaPrivateKey = '''-----BEGIN PGP PRIVATE KEY BLOCK-----

xcLYBGPc3wYBCADPiGAZfRj0a7kmYHrVZwetSscgDIm+kcYPDRBBclWji2qF
shEJCnzdf85pQkEqSLr3T1w2R7WZ56t6x4JZBduyVAyoTLHJJD6FWaAjL1zv
/lVq9aVumII2sC6SCIcoaNMMGvEDbaCjgJRCpI5v8j/o/dFE3mZ1kvn54Zpl
mw6khybnFGU2NrieKaO0wwp43vFHCc+P0Bt0shOUhKQ0y+dOiVOyJppwGRau
ZhljQMLx5CeqhfRhnT0xFF5VnccA/OwmAANuXYr0j1H70bdiRwDPS4ZOQt0x
VNL3L+PhYk+PjJi7w1IxwDQOoRKsiidSVm+C9ifi7QpFY83CzpDObqiZABEB
AAEAB/0XHw0B2fedR6Elnusgem2XB3U+41a3VhtYUu7EM95Jrb8s7QVL2hDG
RrZy8LA860R1SDCwVXXskyx+LdseWvI6oHWWjJDkJXcXuUAHm3/BtzbCB2Mq
erBLMn7Fw1B3lpIoz5mZda3HeYxLDnVWEInBRgH6J8MHh1v1VIa0mj1b5AVA
UesTnbY30RkL2oAHiUom+Z6ZAUS+7CzL/pPEbFVoclT3aEmEH9Y41aGCPLHK
SUvffZ+NxacgmgjMrMun7HrudQj4Z70QvsnBCkA4OZ9V1IdYH+MOFV9rorRe
dGJ3NjW0WK/oTffRMZQ6k79SsY2K0/rgOa7Hm1TXbb88telHBAD9gHxFhP7g
LpyBMTpio5S0hM5GcXI0wQUjFl5TkLcC21bKu/wIHSLqCwQYwVXJlw0qbenh
vb9C++G5VYtscvPz+NsK/zSMrRYKADS/EJtNECSPkgM0U14TD4EvwyPvS7oi
tGPJMWlwoiokyIvOF7f6ZHOQxm68XRPOnaCC1Ph+OwQA0ZPsK1lTsJ9mHcy9
esK2vtOqgIY0m5OLbkBtvkKSl9BP0HFzTxRh41YqXZ6h7EKXhc7VOJ16jA3I
hHk9fCvA43US5h3l9QYJeIOCszJQXYhbLnW7eOd8TEXIVU6Mmb6ZwJopO93l
RAXYBEWR6FDwmQssTBumXJaHM9VOo2O+ozsD/26vPilF+znF4DZuF3A6Y42c
1oTO84D/N+T0YKJ784GdCRQuj+7vXoWeO7CzN+sK9sdgyclZgFfKGRDwu5Wl
YKFQaFnqSO6V9veESC8F6+OpuDXB80tsgh9dicMLVuJMC9hOKPrbC5ITQF0R
iggZgaDh2c3KGWEfIFGht/ibT4MDPg/NHHJzYSBwZ3Aga2V5IDx0ZXN0QGR1
bW15LmNvbT7CwHUEEAEIACkFAmPc3wYGCwkHCAMCCRAiE96TkTdJUAQVCAoC
AxYCAQIZAQIbAwIeAQAAsIwIAKmgHxdnroWM/ccxOJi4v7n9Ls8VcC1IlRwo
f/u9Ax6n14ThPK6PDC8Ur3Fw2BF3Moisa1Qzq8hCynBb/rkGWb5vWLfMtkYf
Pahgvhsmg6TXG/W1LBkpyTOFii+1Pci0o2bg3HKU+8GV++R9vfQQOnCVYx+m
Jc37Q6F4HSz6wX+/rAPY/30X++ltw/3vgkQZI0b0NHUgjdJwzDHRixmsUtjX
RWxcZ4cWsG+93VtjD7oqwJB4Yp2rJhQP4gTR7yc1OXPAJ6T40J+iDa5zZi4r
c5/qTrKJrEXFbeYjeml57r2huX03t0vEW2+6lobu/4KSd9Uni+dn65HEnl8x
GlnG6VXHwtgEY9zfBgEIAOGppdGsY7GS/YNzSvu7NzG4jtwQBifbhu7URiHg
MCbFELm5w/+2C6GfHkGlXJd4Ex+QMN+qUTRTugiXV7Y4ZT8efyDwwEpGpeeq
pv9CLygHNj40/tiDPGphMHbJiFKcW5fbBSzJOJpV6OFq0r/A2ZFTiP1/QAwm
gTaojwM8aJizxzKizU72jp7Ak6Ajz5ayEvbDfkeVc21XIj0ezkVs4JRk6Cq2
Afnef7EBWgDiEpYUuRyTJbdzlLVugc5mh6maSTyOOBxpwsi36BJzhX/Vzm42
LAx4/PXj2bulmqN3BMUXq22CVWCHz91YlE7aHvrbkwlfsE0EJB9M3RK3YLIL
dl0AEQEAAQAH/R/kuL1iFnL9+duOu23Jn3rlATfkAeK3OaJemQznoRaRqpP9
R9DHu2wbz4xqoSP9QgKnf+jUqwZwwO2+6hQkc1bQ6hnPPPYidwc/jLut8HlB
T67KEayrG6pTUySuxhga5i0XtOsIA3p4ouHdFa0pRfaurkFZr0UoWgHOH+xO
qN/P4NyEIBZQ/dTisFoZEEChfhERDmqbNAXMa3lAoE/uiJcWA4Y6E1uaRqbl
ffq5XFRT340/eSzQ+zoh8GI4j2ebZyCDJX/omBt8swVrcxezdp25f6bQ6eHn
JQLAOnxzsE9KRnngGYP7cL9GrsP4df7fYLQgUsBP+8Yg2h4W5qU6LVEEAPoS
QJBetTz6x8+uYkLzUoQ+PuF06UCDoO9tflw4ZlscyTOLIKum9DucDAc/j5jh
g2H3Z5aio5vr4cfttkCQ7nsr/1K5JwUSwKYfdk6+V1rMteeXyTUWWn6M6Rpq
n8kUe4BfFVUP1rH/y+nY+nqMjmESYBHul44Rrzr0AnVm8AgpBADnA0DZHEfk
iqeLKtTfaNsto7d+xozIy6gYbO1xsKKC71y6hHswYqbEIB7FNpwdwuD4Qmy0
XwfiCa4LK+FVEBvJ+f9s13alOJN7p5s8ValWbP+2DfB6AdzTiVsVQbi9qOH9
M0BzhfdItnF0bFwZP7TyhVzfrKlqbEmQhBVl5LnTFQP+PKTLJbqGTnR3Wcpz
WFXTwKl9Mzw78DW6UMt3X84LMPMRu54i1g03IhS1hsDaOKV/EnK7fV8fgJnl
/aDN2dORUMV72Ky8/Svpb4keAsSSPm0SXCoVdpW8M5HRgHNRMY7MV9eBY/yK
0siOz7TtUekVp6WBYtiRB+Ube2+TTlkjLV1Go8LAXwQYAQgAEwUCY9zfBgkQ
IhPek5E3SVACGwwAAOGHCAC7AgulhsAZId2BctmcF6U/XOM0l/D0in0W7m3R
QsftoNTSRVuD1YrAD6RPxVjSA9JGPIuY7CdjL9rfeX7VTyJetJFgYg2UWsq5
x9BxaROITygVtngrhzP2eW2iApZXuspwJDwE8oyye0NHwnxtLfJ5YXKES0sU
NhOio/W7Z+c+nq6emzbtrjiwgwFc2FU+AnQL59Ni99i0EUKAIHx5XjbdGmaU
oeHZr6OQoVnaBGBjO9+/a6N97pe4fbegYiP9j8N0FpolaODkvQRmfYmA+3ZZ
+8xT7uivGp4Dgqbz4Q20p7ppHWTuX+3S3TtLlAxI0k1h/gDo839hTUIsc5TH
iTQl
=KyHf
-----END PGP PRIVATE KEY BLOCK-----
''';
      final deArmor = Armor.decode(rsaPrivateKey);
      expect(deArmor['type'], ArmorType.privateKey);
      final packetList = PacketList.packetDecode(deArmor['data']);
      for (final packet in packetList) {
        if (packet.tag == PacketTag.secretKey) {
          final key = packet as SecretKeyPacket;
          final publicParams = key.publicKey.publicParams as RSAPublicParams;
          final secretParams = key.secretParams as RSASecretParams;

          expect(key.fingerprint, '93456c517e3eddb679bb510c2213de9391374950');
          expect(key.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP!.modInverse(secretParams.primeQ!));
          expect(publicParams.modulus, secretParams.modulus);
        }
        if (packet.tag == PacketTag.secretSubkey) {
          final subkey = packet as SecretSubkeyPacket;
          final publicParams = subkey.publicKey.publicParams as RSAPublicParams;
          final secretParams = subkey.secretParams as RSASecretParams;

          expect(subkey.fingerprint, 'c503083b150f47a5d6fdb661c865808a31866def');
          expect(subkey.algorithm, KeyAlgorithm.rsaEncryptSign);
          expect(secretParams.pInv, secretParams.primeP!.modInverse(secretParams.primeQ!));
          expect(publicParams.modulus, secretParams.modulus);
        }
      }
    }));
  });
}
