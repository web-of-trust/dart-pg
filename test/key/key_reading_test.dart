import 'package:dart_pg/src/common/armor.dart';
import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/armor_type.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/openpgp.dart';
import 'package:test/test.dart';

void main() {
  group('Key reading', () {
    const userID = 'Dart Privacy Guard <dartpg@openpgp.example.com>';

    test('RSA key', () {
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBGc/4FEBCACZXe5kmfKWChtAGdoYRxRkEcfm0Ne431ovB4QS3zIOoclfyA7j
gyq1UAhKbsYhZmTKxx0FO5/HKOO2ojJU3AeKbLP+xhH8yVdEK5JiySvX/16Tz27d
+r5WGLkjZMYZAxWW9hdfurajYp8vcdACvErKMXShXUR9npCKH5O0QBagxMg6vczf
JfNG1qWJ9aeFO7yffUt9n+39ru3Cc67EAp7m29Wowto15xmeXCPkYEgE+BM+86AH
GqihOERjPCzWeFVLRuCwj2YjmZvtMh9A2gx5K6dMQ5viMDsTSoB0DEZzvY+Q7gr7
/qiWCpSfmy3gvmReOvMzk8uI7+Nt6vdJia4vABEBAAG0L0RhcnQgUHJpdmFjeSBH
dWFyZCA8ZGFydHBnQG9wZW5wZ3AuZXhhbXBsZS5jb20+iQFRBBMBCAA7FiEEXMzt
pU+RcIn4xIgABTI3KgKPL/UFAmc/4FECGwMFCwkIBwICIgIGFQoJCAsCBBYCAwEC
HgcCF4AACgkQBTI3KgKPL/UGsgf+MZ4jtjY6DLCSirAJkV31cvzawO3KgSBXGuBf
bnZxWniWwfzJF1n38HBMIpfx9wOpks7b6js5TuBaoguQ3xc8URrtywO4HavM3fd2
kzWeKeePQQVsdmbBJS497MXHo+WiztAl+x7wTtAO08goSKefDuhst1G14AiUxeaZ
YPZpq8FdGe+LI6tTuc/FA/0P78g21P82WoWti23OpPKjDh7TS2T47DJ/dUEEavwV
6mT7rdLoRqrZtDj52rNzPOf4vyfBQe8X5ZQljSUcbUBqLE8LeD6z8AYpw/0Iisc+
xg4TRq38ccCG6AOWCIAExWo2OgIZkU7tKURKstPXRAa2eQWEg7kBDQRnP+BRAQgA
lK7KSXI6cbgCihf9oD1iaIJE7pPmGvgVA44DyNwqYfAD5BX1XLfjTcEltcQ+gYP5
Rkh9IXnV1Ew1cgiF3dTyPLVhIweNWkbtoVSfdPFAKOylZkk98zUkQpTSTzdH3+yl
euyuitz3Fotgs1efDWUgStpGakKc0EQhR6vDWKOjUJye8oWMR93X1uxdIVcDM3IM
PEorTUVtLzZSQyUHQG73h4fMN7mUPrRALO0LGVXVY9ie0RTjgA9SdzZZxMRN5nGs
MD4tiiyr/JRsztIyzT4hJyg+uC2zRPEA6/q9m0egseP3BCeal7h01BEm5T8JJD5V
t8L9rQ3UakGSshiziCntCwARAQABiQE2BBgBCAAgFiEEXMztpU+RcIn4xIgABTI3
KgKPL/UFAmc/4FECGwwACgkQBTI3KgKPL/Uzpwf/f9uukiyNC4QNF7cfgSzoZMRQ
oOeg/LqKrk/Ig036EI65xwTHm8DG0fvejIpVPrmPM0nKVhBacTTU5M6nunN5D5RJ
FlO7GPjgZt0PmBEJ/VWiiwV9tww9hegW9pFRrVswM8lrocQ87XGcIxCrQi48UpHp
5Us0Q50tqWlrMVw2TehgPDLJtmpdta4OBG8DdfwugLIrCjD6yxvPYOvX0mQDlY5G
2v9w+m3t60KSt9okDs3LouipniCA6brtpcQ9XPw7w+Is3hSSk0g8Zbm2lVVZVRiP
hrmPD+bTB7WO025GVa9Kl9vs87rAeEVXtEXJiNxlTP8BGSRzz1ayKQ9Y4UcY2Q==
=S9XV
-----END PGP PUBLIC KEY BLOCK-----
''';
      final publicKey = OpenPGP.readPublicKey(armored);
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
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=3nnd
-----END PGP PUBLIC KEY BLOCK-----
''';
      final publicKey = OpenPGP.readPublicKey(armored);
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
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mG8EZz/5iRMFK4EEACIDAwR3cUlciuVCSwGLA4sH6SwA1axNDMU3GqnHOOmCVoM0
qOAX9FdVeP0DqixqjRYm2qQoUpm+QBK84KA5oGfcYNRmYXwYnC64s05yLQkL836D
mcV38F5c0k3IQIwhuWVwu320L0RhcnQgUHJpdmFjeSBHdWFyZCA8ZGFydHBnQG9w
ZW5wZ3AuZXhhbXBsZS5jb20+iLMEExMJADsWIQSjJRB+ZryrPupAdVA5bsuLuG0Z
IgUCZz/5iQIbAwULCQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRA5bsuLuG0Z
InjBAX9bv51DhgTNGDot6gTEKJ7c0FypBuPZPlNOKMCshtvu36+jiJyMpGBaR/C+
CB8wctkBgNT0/5Mj1e+UXqFAmflWmODnszrYpdiGSF2GJxVwOBLJeFVqPQtl2mSn
mKmhhoVy3bhzBGc/+YkSBSuBBAAiAwME6+LPwcbdvoEdxPA2L002pKXp8Nt7PxIs
jUegQRw2bTQXMlu5zplsUNprWJZ1W/iqLhmEH8eLONxcuzVEQMb3dCImxBzmL3Y5
HxGGti81EsU7JBIZxHKhl85RY78HdHgCAwEJCYiYBBgTCQAgFiEEoyUQfma8qz7q
QHVQOW7Li7htGSIFAmc/+YkCGwwACgkQOW7Li7htGSJT3AGAgueSdnW+Lvrv2K9V
fqgHGB2NDYsdLdXOIHardOmkFmD3rTbjsjHkQrLCs/lCQkVhAYCxmcY10PcZBwYq
mzhn+ek2wQOTGM2wO3qJVZ9Z+z5kkQXH6JtyfkZATJgA/kougNs=
=K1/q
-----END PGP PUBLIC KEY BLOCK-----
''';
      final publicKey = OpenPGP.readPublicKey(armored);
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
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mFMEZz/50BMJKyQDAwIIAQEHAgMEnXlquLQ8KrfXtrCZ000jDP7I5nXzJQKDws4C
ZgRpECoCHUeYCdIrl3iLUJfYzb9Qq6nt/8oP+jljqiJ35W5NlLQvRGFydCBQcml2
YWN5IEd1YXJkIDxkYXJ0cGdAb3BlbnBncC5leGFtcGxlLmNvbT6IkwQTEwgAOxYh
BM0bWxQpT4C+Zc7775lRIZ/J3pV4BQJnP/nQAhsDBQsJCAcCAiICBhUKCQgLAgQW
AgMBAh4HAheAAAoJEJlRIZ/J3pV4v3oA/R9IMDJklqQ7qUp20updBhqAbifSELId
xbd886G8hPgiAP0bpKSgkad2xFUSuO8o4b8menOFbFQphPIf/E+CWstwBLhXBGc/
+dASCSskAwMCCAEBBwIDBGuDRKYwfAtThNOAM51Is4J1BYPN6qZCTN0c9ldSQzGS
VO0lI/BV2JJsuQqI0Pne08Y7og4bhyv9S+D+wcU8sv0DAQgHiHgEGBMIACAWIQTN
G1sUKU+AvmXO+++ZUSGfyd6VeAUCZz/50AIbDAAKCRCZUSGfyd6VeMTKAQCIrK5W
d0O6gwPJ4rSHWo13Q0K9Lth8ZBtXySqZZ/XSBwEAj22bXtH3QkS/K70fExKX4KZ7
k49k9YikNemTd0HPLRc=
=38Dv
-----END PGP PUBLIC KEY BLOCK-----
''';
      final publicKey = OpenPGP.readPublicKey(armored);
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
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZz/6BhYJKwYBBAHaRw8BAQdAZQAdPHBwHpMPvaCgVCkt/eMCp1ubVxnC/U3a
aMF98SC0L0RhcnQgUHJpdmFjeSBHdWFyZCA8ZGFydHBnQG9wZW5wZ3AuZXhhbXBs
ZS5jb20+iJMEExYKADsWIQQRSLKiT1gJd8J7JiI+1HXdIS0iHgUCZz/6BgIbAwUL
CQgHAgIiAgYVCgkICwIEFgIDAQIeBwIXgAAKCRA+1HXdIS0iHrifAQDPuCf7ztzy
K9opPkJ2aw7SR/IFTE7dfdIuOTDud+Ph4AEA4YRvlmHv27VVAsS8XoDxT+t1tbkA
xgiwXtqXA2t/Ewy4OARnP/oGEgorBgEEAZdVAQUBAQdACcGlnxIiapTiJPzvYtjz
GgwZm0VDgRxkHRUTym4n6X8DAQgHiHgEGBYKACAWIQQRSLKiT1gJd8J7JiI+1HXd
IS0iHgUCZz/6BgIbDAAKCRA+1HXdIS0iHrDSAP0Q/+hfme0EqcVJf/Z38dQwhXIM
Dy6c8mMkLVpS/zXLOAEAp3nZkkgY1MgZAfbx4BEq+uJv801qCBNeThFeOe8/3gs=
=/O/r
-----END PGP PUBLIC KEY BLOCK-----
''';
      final publicKey = OpenPGP.readPublicKey(armored);
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
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: PHP Privacy v2

xioGZ0/jphsAAAAgy19s9qAQsttkAS7gPmFeakgJwkKklQVReq/oPNJVWKrCuwYfGwgAAABcBQJn
T+OmIiEGeyUi0XrLxokVQFD7GiRV+fyaRjGK1u9QOdPm47wEpnkJEHslItF6y8aJAhsDAwsHCQQi
AQIDBRUIDAoOBRYAAQIDAh4LDScHAQkBBwIJAgcDCQMAAAAAx94QMOS423OajdIBpQ7T4MklWxyz
4SNy5d9A3+a7huNEw6qmaJ+pqVGcrNctLB9qWyD4+xjDtMLqHYOeNUsunRUUaBM8BbFCb86wljnA
1RpABwXNL0RhcnQgUHJpdmFjeSBHdWFyZCA8ZGFydHBnQG9wZW5wZ3AuZXhhbXBsZS5jb20+wpUG
EBsIAAAANgUCZ0/jpiIhBnslItF6y8aJFUBQ+xokVfn8mkYxitbvUDnT5uO8BKZ5CRB7JSLResvG
iQIZAQAAAADh1RDsF0xb6N2mB4vw9rYIrNcKdWSwPb0IBY6kNrnN84nMcGCseJ9JWpX+4le3HP/s
Ej9rf8N+GfwQHY7FqUk4m+Mmrg9FSY8rtgtQ/WF/pPBeC80qTmd1eWVuIFZhbiBOZ3V5ZW4gPG5n
dXllbm52MTk4MUBnbWFpbC5jb20+wpIGEBsIAAAAMwUCZ0/jpiIhBnslItF6y8aJFUBQ+xokVfn8
mkYxitbvUDnT5uO8BKZ5CRB7JSLResvGiQAAAADyNxAEWM9B3Ds6IOlYh2UIJ6BFMuDamUakpZff
sKKi6VPlhwTKb80sbAMCI2QeBpKkFR6j+4hBuleDEm34RE0Qo2P9/e8eJLUt6QvNwv8XrFMHDs4q
BmdP46YZAAAAIDv21k8ovP04IZRAc+Wiq+zFU0HW4P/GA5bLvCCPYHltwpUGGBsIAAAANgUCZ0/j
piIhBnslItF6y8aJFUBQ+xokVfn8mkYxitbvUDnT5uO8BKZ5CRB7JSLResvGiQIbDAAAAAAiEhAM
bPIvl2dct0Etc792kYzRRbUC3XDl5uzoLJj59aBkhkE+e5nX8j6hCfYSjQnPq9oKmMeOjdgkjeDM
fjfQblPSXk32Zpv5RXzNhOIelkIuA9USba2Zw7ZRB4iuDfOgEJAw7VEt
-----END PGP PUBLIC KEY BLOCK-----
''';
      final publicKey = OpenPGP.readPublicKey(armored);
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
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

xkMGZ0/jphwAAAA5a1Aan5R/DuK8jXNrY9+z7IKjQ8NHO6J1CTodHHpDslwa7V85AavFpaHoxlp0
yn2fJX2fSnJkqdsAwsAtBh8cCAAAAFwFAmdP46ciIQaTh3wqdlbkHo45oW1AVhRmOkxVk9ozBveA
NfRmZpxgUQkQk4d8KnZW5B4CGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcBCQEHAgkCBwMJ
AwAAAABauRD3wkQRbuI3zf+UyqDl2Y1qlqCHtdViFqwgyZE4mhZZYIrmfHYguy7GJm3FCb4vDZJM
X6qSmyH2kclVUvp3VGJXpOo35lDUidSAIYffeYT7jC2KIz7IcA5WAiHIDW7+5rQ30yehH3MOBhjR
dKNWDdrezDt8A6pl9pRFMlzO+YGQfjwAzS9EYXJ0IFByaXZhY3kgR3VhcmQgPGRhcnRwZ0BvcGVu
cGdwLmV4YW1wbGUuY29tPsLABwYQHAgAAAA2BQJnT+OnIiEGk4d8KnZW5B6OOaFtQFYUZjpMVZPa
Mwb3gDX0ZmacYFEJEJOHfCp2VuQeAhkBAAAAAFvNEKq2qVYMJA+GbX7k4Qk+0pnJFW2+kEQ4qmDE
HhYIoeD9YnicGqr5+479nt9AqxQVV1IJT8mwxqQYIrBsoWxy83Z4o7A9umbkn4CmGFi61EbJ/JjZ
NhLtut2DSlWz9wntNQArseGnHhGjGrupJqiNhkyeCdhJ09grcds6mS1JI4i+EQDNKk5ndXllbiBW
YW4gTmd1eWVuIDxuZ3V5ZW5udjE5ODFAZ21haWwuY29tPsLABAYQHAgAAAAzBQJnT+OnIiEGk4d8
KnZW5B6OOaFtQFYUZjpMVZPaMwb3gDX0ZmacYFEJEJOHfCp2VuQeAAAAAPx5EGrwf9dxyc8Zcf3T
WTH678WXGljJ5QML4S98Po7Q8vcE+1IGEE/hjOpi/cTpL9z+2lQ6XvLYVD54YuFzsEj11zhMM1gc
4pASBABfwzft/LL75Gr8NvTvc7/oD1PNnXOaoLjKfuXIlFAMel73EQqtp9MR7uQ3iDI7WIXmTG/f
mnT0KQDOQgZnT+OnGgAAADiY/+RbigV4l1adpmwFDGKZLpK7qYHnSuxjknWgOD48e9nDdZ3gkW+o
TOZaHsI546Kexs04A4ZCv8LABwYYHAgAAAA2BQJnT+OnIiEGk4d8KnZW5B6OOaFtQFYUZjpMVZPa
Mwb3gDX0ZmacYFEJEJOHfCp2VuQeAhsMAAAAAMM5EPfNxWSEvc5dMhOkM8a9a8EFgF8qOkwJj9sQ
ISt80um5TscuNDSqmwCJCTLXDhblTcwseZGrBjlrnfij7+9VPQDPRzaYUSopXQDG4l8JFKpYxvEY
4xo3/Pw117VEfs6lTc8PLF+NkIlv6Ip88od/3Op2bjJfQX57cOQwx65hc/bdCgDVEEdmNh5TAjGf
FmXTxip3kr4=
-----END PGP PUBLIC KEY BLOCK-----
''';
      final publicKey = OpenPGP.readPublicKey(armored);
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
      const armored = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
7z/eCw==
-----END PGP PUBLIC KEY BLOCK-----
''';

      final publicKeys = OpenPGP.readPublicKeys(armored).toList();
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
