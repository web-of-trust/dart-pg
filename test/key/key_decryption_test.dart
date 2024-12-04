import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/key/private_key.dart';
import 'package:test/test.dart';

void main() {
  group('Key decryption', () {
    const userID = 'Dart Privacy Guard <dartpg@openpgp.example.com>';
    const passphrase = 'password';

    test('RSA key', () {
      const armored = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
=QeXb
-----END PGP PRIVATE KEY BLOCK-----
''';
      final privateKey = PrivateKey.fromArmored(armored).decrypt(passphrase);
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
    });

    test('DSA & ElGamal key', () {
      const armored = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
CorNeTDAKJEwL5SJhzt+bmo+
=7ZVq
-----END PGP PRIVATE KEY BLOCK-----
''';
      final privateKey = PrivateKey.fromArmored(armored).decrypt(passphrase);
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
    });

    test('ECC NIST P-384 key', () {
      const armored = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

lNIEZz/5iRMFK4EEACIDAwR3cUlciuVCSwGLA4sH6SwA1axNDMU3GqnHOOmCVoM0
qOAX9FdVeP0DqixqjRYm2qQoUpm+QBK84KA5oGfcYNRmYXwYnC64s05yLQkL836D
mcV38F5c0k3IQIwhuWVwu33+BwMCYJx1nYlH0Mj4vl/mSNGARY0WUyL0C6UJ7S65
Ly16TGI3V490OtTlB4B8UIL0s4l0odNR1A6zF8oGXlNBBWe/Q9U+W34J/q+/zKyF
/rZ6EIUfGoOh2kRLeRVWcvjXI+m0L0RhcnQgUHJpdmFjeSBHdWFyZCA8ZGFydHBn
QG9wZW5wZ3AuZXhhbXBsZS5jb20+iLMEExMJADsWIQSjJRB+ZryrPupAdVA5bsuL
uG0ZIgUCZz/5iQIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRA5bsuL
uG0ZInjBAX9bv51DhgTNGDot6gTEKJ7c0FypBuPZPlNOKMCshtvu36+jiJyMpGBa
R/C+CB8wctkBgNT0/5Mj1e+UXqFAmflWmODnszrYpdiGSF2GJxVwOBLJeFVqPQtl
2mSnmKmhhoVy3ZzWBGc/+YkSBSuBBAAiAwME6+LPwcbdvoEdxPA2L002pKXp8Nt7
PxIsjUegQRw2bTQXMlu5zplsUNprWJZ1W/iqLhmEH8eLONxcuzVEQMb3dCImxBzm
L3Y5HxGGti81EsU7JBIZxHKhl85RY78HdHgCAwEJCf4HAwIIaqT4lafbcPhMsDaE
o9wLpC5rY6k28ax3dHv1RLibxxcZafaTP1eKy+W0fBtOm1vDkkc/HCxsFBtIkZ/c
/rfA30/p6jibrlfk4qOVlSGYPN5QjexvmaK1Us46fWLEe4iYBBgTCQAgFiEEoyUQ
fma8qz7qQHVQOW7Li7htGSIFAmc/+YkCGwwACgkQOW7Li7htGSJT3AGAgueSdnW+
Lvrv2K9VfqgHGB2NDYsdLdXOIHardOmkFmD3rTbjsjHkQrLCs/lCQkVhAYCxmcY1
0PcZBwYqmzhn+ek2wQOTGM2wO3qJVZ9Z+z5kkQXH6JtyfkZATJgA/kougNs=
=rr8a
-----END PGP PRIVATE KEY BLOCK-----
''';
      final privateKey = PrivateKey.fromArmored(armored).decrypt(passphrase);
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
    });

    test('ECC Brainpool P-256 key', () {
      const armored = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

lKYEZz/50BMJKyQDAwIIAQEHAgMEnXlquLQ8KrfXtrCZ000jDP7I5nXzJQKDws4C
ZgRpECoCHUeYCdIrl3iLUJfYzb9Qq6nt/8oP+jljqiJ35W5NlP4HAwI3GD01hi3V
P/hQXGRXNxRo8r4melKsvJRp2VTArNRXunWZFvxjQTqFbnF3OHkh8Fe7P6drfUlU
6vWS3K/AG+uxaN112eUP5DqktHorP8pKtC9EYXJ0IFByaXZhY3kgR3VhcmQgPGRh
cnRwZ0BvcGVucGdwLmV4YW1wbGUuY29tPoiTBBMTCAA7FiEEzRtbFClPgL5lzvvv
mVEhn8nelXgFAmc/+dACGwMFCwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ
mVEhn8nelXi/egD9H0gwMmSWpDupSnbS6l0GGoBuJ9IQsh3Ft3zzobyE+CIA/Ruk
pKCRp3bEVRK47yjhvyZ6c4VsVCmE8h/8T4Jay3AEnKoEZz/50BIJKyQDAwIIAQEH
AgMEa4NEpjB8C1OE04AznUizgnUFg83qpkJM3Rz2V1JDMZJU7SUj8FXYkmy5CojQ
+d7TxjuiDhuHK/1L4P7BxTyy/QMBCAf+BwMCLM2ShOzK5gv4r+BsOIlgMyPBEsUc
/sO1PLeLyEQoCa5CcHATAtPrJfBHhD+TJbFxOA0HBnCtvQn47oGBkvnBCL4x94Q1
McHOENbwToV6Voh4BBgTCAAgFiEEzRtbFClPgL5lzvvvmVEhn8nelXgFAmc/+dAC
GwwACgkQmVEhn8nelXjEygEAiKyuVndDuoMDyeK0h1qNd0NCvS7YfGQbV8kqmWf1
0gcBAI9tm17R90JEvyu9HxMSl+Cme5OPZPWIpDXpk3dBzy0X
=CNK9
-----END PGP PRIVATE KEY BLOCK-----
''';
      final privateKey = PrivateKey.fromArmored(armored).decrypt(passphrase);
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
    });

    test('ECC Curve 25519 key', () {
      const armored = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEZz/6BhYJKwYBBAHaRw8BAQdAZQAdPHBwHpMPvaCgVCkt/eMCp1ubVxnC/U3a
aMF98SD+BwMCG2M/g+96Esj4hyo7hP1EHf6XFy/uhDRNcoTjWNnPF+KVBLNdGn0o
UjSHZXBi0ScUcW6e/SfT4B77HNS8Abr7Ersx5PVWmYARpn2gVNFqlLQvRGFydCBQ
cml2YWN5IEd1YXJkIDxkYXJ0cGdAb3BlbnBncC5leGFtcGxlLmNvbT6IkwQTFgoA
OxYhBBFIsqJPWAl3wnsmIj7Udd0hLSIeBQJnP/oGAhsDBQsJCAcCAiICBhUKCQgL
AgQWAgMBAh4HAheAAAoJED7Udd0hLSIeuJ8BAM+4J/vO3PIr2ik+QnZrDtJH8gVM
Tt190i45MO534+HgAQDhhG+WYe/btVUCxLxegPFP63W1uQDGCLBe2pcDa38TDJyL
BGc/+gYSCisGAQQBl1UBBQEBB0AJwaWfEiJqlOIk/O9i2PMaDBmbRUOBHGQdFRPK
bifpfwMBCAf+BwMCCMCreqPjxcX45R3/KPQFMRNxZ0l8OCBHq5IByLEAAOGszlRo
yrLREP280yDxw39q0VSIkn2tmM7bleGk71aJ9UzTxcMZzdCYT2f8tmsQOYh4BBgW
CgAgFiEEEUiyok9YCXfCeyYiPtR13SEtIh4FAmc/+gYCGwwACgkQPtR13SEtIh6w
0gD9EP/oX5ntBKnFSX/2d/HUMIVyDA8unPJjJC1aUv81yzgBAKd52ZJIGNTIGQH2
8eARKvrib/NNaggTXk4RXjnvP94L
=4mmg
-----END PGP PRIVATE KEY BLOCK-----
''';
      final privateKey = PrivateKey.fromArmored(armored).decrypt(passphrase);
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
    });

    test('Rfc9580 Curve 25519 key', () {
      const armored = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

xX0GZ0/8WhsAAAAgHDf+yTRCzA8vM6PV+ovg3URqlceQQUcH/Ekc7ZsR9Q3+HQcLAwiv+8mof0Fc
BuCm/9pWdojyrmg+x9KU0U+hzPx2wGmqtaz9WIIEW9PbTkBZc/5BCB15qC6ZLvL3oQc9h4XmHwhg
a/TtUUpYW6cvk45KzsK7Bh8bCAAAAFwFAmdP/FsiIQaWDEY7sAo6ZqJa+4tswpHYFSCDSFPzJdEJ
Yvcai0SjTAkQlgxGO7AKOmYCGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcBCQEHAgkCBwMJ
AwAAAAAqIhCiMxuCDvJ0r1dyF9hUSzRiXZqzB3uhdMrkX1YtDPV7RYzfulWDImcd8siqveYshD4w
uo6RBzsIt6aJrKUZSlzd1HR9NuZKEWaB9TYuZOo0Cc0vRGFydCBQcml2YWN5IEd1YXJkIDxkYXJ0
cGdAb3BlbnBncC5leGFtcGxlLmNvbT7ClQYQGwgAAAA2BQJnT/xbIiEGlgxGO7AKOmaiWvuLbMKR
2BUgg0hT8yXRCWL3GotEo0wJEJYMRjuwCjpmAhkBAAAAAAYjEJdMNIo0MDDvlfOiEBlzQKdyvNhf
OwORi8ABLx96zDD6cj+0l/JMyi75OL5uuNZDdxgFrqTYQ4/2r6F3wuTXBpKGUBouZBO7Y+QgI1Ww
kJoPzSpOZ3V5ZW4gVmFuIE5ndXllbiA8bmd1eWVubnYxOTgxQGdtYWlsLmNvbT7CkgYQGwgAAAAz
BQJnT/xbIiEGlgxGO7AKOmaiWvuLbMKR2BUgg0hT8yXRCWL3GotEo0wJEJYMRjuwCjpmAAAAADKm
EOpBOnKA+bNtXdYqExEUv8KwwiiVpLdUqSwlsKONUZMhr/NaWBafrsmUhQMVnir4x3JWVMs2aHVO
3t0udVsFcBYQcm7vQcXsKBLeyCCWUzMHx30GZ0/8WxkAAAAgzmnTRHsYD3OeQDlZPC4Ujcqlkl+6
iesJlNX9VYO4/Ar+HQcLAwhZpk+g24kZSeAivkvADh9xHx7hVPD6hl99bI30XqNdIMK2VcY/Zk3c
k949Su5SV/sELKg9EikzZdEoiY+N7rWCHJXFxRNbp9scCSiJu8KVBhgbCAAAADYFAmdP/FsiIQaW
DEY7sAo6ZqJa+4tswpHYFSCDSFPzJdEJYvcai0SjTAkQlgxGO7AKOmYCGwwAAAAA0RcQJB9YvxrM
NDm6QTmbvRO5EjvPyQf9I1gqhYkVZExIvt/x5vpX/ID29c91PagKcr4eoJrl9Xyfn8ksYFkmXI/B
C8sssUAhAtMI5sgtlfA7Ow7VHjDLcQ0doBgA9J4afJjd12/e+PYN4Kdqvt5Gbv5ltA==
-----END PGP PRIVATE KEY BLOCK-----
''';
      final privateKey = PrivateKey.fromArmored(armored).decrypt(passphrase);
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
    });

    test('Rfc9580 Curve 448 key', () {
      const armored = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----

xa8GZ0/8WxwAAAA5yymL3ZZ7U9OrS3LdxuhvSc/SMFFNYSwyB9f4JHMgw/DxUx4+81alHHCjGNRE
Lylg9n81LWeN0SCA/h0HCwMIBg46deIoPR3gg3z8j3H3k3h4a0NDBbT5iTOpswmrc6NdU4X1zabs
wUt1SSLtm9LPyXlOyIpQeE3CfDlYmNDzs7Gz7MIa+dbimHUmKrOWvAtlKZeIBtowletTex9cxkdv
JyrcDVZGwsAtBh8cCAAAAFwFAmdP/FsiIQZcGXS4BAC8Li+HPo5erpI7ttQLRDRvqUzZ/YMZCmIS
WAkQXBl0uAQAvC4CGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcBCQEHAgkCBwMJAwAAAABW
ARABLtqQ+hSn18x6xfVEaXx8BqT/L3ghgvGeYI+Ou7b/bDnLoTySTQslRxWGYhUFOkMiPUPvxyoo
aeH8iPj+QsS5kbPoIWicG9QAbEeBjGWzGezqMt+B0DuIiQGGiE/FAjLdbOM2ctvBBRvk2TeGAZ7Y
VTHXEv7hxSWK0koylRtNmCIAzS9EYXJ0IFByaXZhY3kgR3VhcmQgPGRhcnRwZ0BvcGVucGdwLmV4
YW1wbGUuY29tPsLABwYQHAgAAAA2BQJnT/xbIiEGXBl0uAQAvC4vhz6OXq6SO7bUC0Q0b6lM2f2D
GQpiElgJEFwZdLgEALwuAhkBAAAAAPHqEBYl8EyZZ87R1GxCa/nbpsV64m/USnwef1z7QP+cotTK
YgQ1belLShpGWsEWlejSAffDWWjTyj4Zet+/ZD8qRArffNTJKckUiQBLo3FRST7q6/+fr05vNVXd
6qzuNRZ8qNEMn0RXWVlknx0ngB+RDY8rxenWE+aX/FJkzAlw2em/KADNKk5ndXllbiBWYW4gTmd1
eWVuIDxuZ3V5ZW5udjE5ODFAZ21haWwuY29tPsLABAYQHAgAAAAzBQJnT/xbIiEGXBl0uAQAvC4v
hz6OXq6SO7bUC0Q0b6lM2f2DGQpiElgJEFwZdLgEALwuAAAAANCTEMNpNd0oX1itofCILqF8O8Na
MlIdTThwhdw2VNWIxj+mdL+WI6N14pybiOy1l487NZRSO3EgmRjYtCyxmfQ7dEOVSkdYy4SylQD2
G3wBZYSq2d03Y4uaV0dcvcImPBBsPfP21Ka40VER9F90WQus0I1y77c4C3KXc4FNl0KIeZlTMADH
rQZnT/xcGgAAADhTie394+2su5pQnDF2EoeexN9C5SexeDqfMeBq6WZG7LEdkJRkrPdNZJsX+pXM
cZYaKMy6NJIfUv4dBwsDCOnMOf3LbUZK4DW7Z5VeIJQATLUbvtUju5uVCeXxx4Me1MivD4eQdCDE
ISRfcRK3oQ1d9FrHbXSV0Y2VU9/dFKcIayJaIKGLeUzG8PHUNTCD9HkSfjTf2x+kwQsu4AtyvGbZ
UL1gwsAHBhgcCAAAADYFAmdP/FwiIQZcGXS4BAC8Li+HPo5erpI7ttQLRDRvqUzZ/YMZCmISWAkQ
XBl0uAQAvC4CGwwAAAAA5wcQcWaN5Sdj4wJxMX/wB9Uhf3hICRUGVFN1iYWnhmUPeJ5b3SnQ3/rl
oQCDLwoWcOkSS4+wQExO4WXxyvUNKJ15HL4YV2nx0VbmgC7GeukcVAdKATn1OO9Nt0MevTxuRW/J
lzIMFLqFsDiKPzuwpZBhzEh+sj0Z3WtqZOueBwxVocwDANUX0mClieCAd2U0VQHW7lMIkRYMY5ZS
x6s=
-----END PGP PRIVATE KEY BLOCK-----
''';
      final privateKey = PrivateKey.fromArmored(armored).decrypt(passphrase);
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
    });
  });
}
