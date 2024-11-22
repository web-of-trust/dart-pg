import 'dart:convert';

import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/ecc.dart';
import 'package:dart_pg/src/enum/key_algorithm.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:dart_pg/src/packet/key/public_material.dart';
import 'package:test/test.dart';

void main() {
  group('Public key', () {
    test('RSA keys', () {
      const keyPacket = '''
BGc/4FEBCACZXe5kmfKWChtAGdoYRxRkEcfm0Ne431ovB4QS3zIOoclfyA7jgyq1UAhKbsYhZmTK
xx0FO5/HKOO2ojJU3AeKbLP+xhH8yVdEK5JiySvX/16Tz27d+r5WGLkjZMYZAxWW9hdfurajYp8v
cdACvErKMXShXUR9npCKH5O0QBagxMg6vczfJfNG1qWJ9aeFO7yffUt9n+39ru3Cc67EAp7m29Wo
wto15xmeXCPkYEgE+BM+86AHGqihOERjPCzWeFVLRuCwj2YjmZvtMh9A2gx5K6dMQ5viMDsTSoB0
DEZzvY+Q7gr7/qiWCpSfmy3gvmReOvMzk8uI7+Nt6vdJia4vABEBAAE=
''';
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(
        publicKey.fingerprint.toHexadecimal(),
        '5ccceda54f917089f8c488000532372a028f2ff5',
      );
      expect(publicKey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(publicKey.keyVersion, 4);
      expect(publicKey.keyStrength, 2048);

      const subkeyPacket = '''
BGc/4FEBCACUrspJcjpxuAKKF/2gPWJogkTuk+Ya+BUDjgPI3Cph8APkFfVct+NNwSW1xD6Bg/lG
SH0hedXUTDVyCIXd1PI8tWEjB41aRu2hVJ908UAo7KVmST3zNSRClNJPN0ff7KV67K6K3PcWi2Cz
V58NZSBK2kZqQpzQRCFHq8NYo6NQnJ7yhYxH3dfW7F0hVwMzcgw8SitNRW0vNlJDJQdAbveHh8w3
uZQ+tEAs7QsZVdVj2J7RFOOAD1J3NlnExE3mcawwPi2KLKv8lGzO0jLNPiEnKD64LbNE8QDr+r2b
R6Cx4/cEJ5qXuHTUESblPwkkPlW3wv2tDdRqQZKyGLOIKe0LABEBAAE=
''';
      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(
        publicSubkey.fingerprint.toHexadecimal(),
        '79fb82ac1204bdc854e87364316ef1539787254f',
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(publicSubkey.keyVersion, 4);
      expect(publicSubkey.keyStrength, 2048);
      expect(publicSubkey.isSubkey, isTrue);
    });

    test('DSA & ElGamal keys', () {
      const keyPacket = '''
BGc/4H8RCAD3gDG7FSfKWRy4/gNe0sgYYgZ4zAFZTLWneObcLYpY+kmwufUIrAG0iWt8kzLbiLon
A1B7ss041yCqJgTHFcttH5nFG/q25MT+xq+V55TRZGzaD6Gy65E++CuS0m3gJmLH14bX6++5Evtc
/bkOTGgIfRGfEH8pL1ePc9ev1EFtmOYgZkX0a7oM8TiNKVNnUKwhuBi7pbC6OEOuDL1HmbsAHIE4
n6mMs3HzJCNEAkvHNcQGZNdn8SD3d3ukljOq03ko+tC2Orys1AwiZokL10EOiZYQZ55KAOFXM/Hu
ayVQ8xR9Zgg8i+8HdjvAzaifH6ThOMDE2I80Yp/jllG/PBBvAQD3msVRxzpaT3WiMeopZAOM+jeF
xwy8bG0W+BOJwn9BjQgAzFLIFwHauCi4ooI0JsndyKE6TCexzA46r0nA/1BcNpRtUlhLsEwJ0app
PkCufixLL0RYKTnxgfrAbxR+mrIPla1djnNysoYj8NfDms6aIoxKzT7gN9WWwgwaTSo7lesJ8gZ6
aZLt1kBEHj+72MUb5Jgynzjd6HA8FwQvXIUaQl0HDmYByzr/hBtVzrog5fSR/jTXX/ZbTivqgHV1
JzT0NlTBrFEGuIFRj54JvEaiYtE/Z/lWkIRmcrAwaSCeutF4w4Xv9BhhGdRtLo2AJCQeR26sOk1k
xihdes4zBrhI+e0wrAG7G4cNOtS090O8tvIWlxlrJXyYmpZR6zHxBYbBIQf+Lk0Jou8CnR1S8oeN
EdBfeuboNWTDVz93iSEBHkSIFfwt07IvHra0wKKkYwX/p8zWyw/Me2e1xtRommFSpIqW9pWimT4b
kTtPqXAwRD4WhfVOnGxzXsXaYSWIf4sr9GusPJTsAi2cdtKTDzXFWDpJDvJ24bPa/P4oEiECno2s
2KkfQqWZbSRbOsDX8/Mdz58XzOWOv3j0A1oLLZFK+a0LiJso31S0jG71IiMFlaXWNQD025UV6Oup
lqe/P6qdArk72Qaum4QBsFfTLyKw12JQc9HPfV4Fst0sSbky+0QqqVfegHnvcnJBrjZ2pahL+EWU
LYR9lty0LinZ0v6+5HtwDA==
''';
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(
        publicKey.fingerprint.toHexadecimal(),
        '9a83344a3711864c1f502094ba727d0f6b50c281',
      );
      expect(publicKey.keyAlgorithm, KeyAlgorithm.dsa);
      expect(publicKey.keyVersion, 4);
      expect(publicKey.keyStrength, 2048);

      const subkeyPacket = '''
BGc/4H8QCACv2nUuptC3DfhXtkI3H825wX+OwZzwOP8MG/JNUut/RoxFDXnld1S/GVz/dDBXs+cM
QY4M9Fe2KfsGbNVeOId8eBENIFE7DBH6Qigh8WkBUueV6qPeFkWVj7u72TwRPjR3A6uAwLv/ZrMZ
JWqD52tDr2YDv8e5LlS8uzVmTYo9nU8ohn3n6KyKNarEhpuXHqo3SHt4H7601Nr3TqdRU5ZWW1F6
QEjj0Mj1st7ctPkMjj4R5IzfRZHyDQIrJA5Vp76cZ+oXZFIgrkWwJ//HZ/txc2PGLYYf6OCgTZRF
Rh720ETDf4arK1FheJ2qVad4YX+21PvdzU8DeIn4McO8QyM7AAMFB/9RdNV1kNfAl7LPOUp46sO/
97esXDT5DfLcBgV+bdUGuQonASsKk53phnwp1mLhfRe1TldkoWpxkOOZAHXDdr+hbSp+UNimK9Bs
X/jCYcQr0Il5Agq8F8Idxrwv2ftlFVAsuDrwyzhGFHFC5mXPeloDG1aF8cyWKXbONM3DzBwISW4p
wKXXYZqqiDgmlQ/anjEExZqmSs6+sqWpl45iAsAB/jYvzuBl06pJFxFJo7TwNAKhgTFHMGlHXjl/
JCbd1xv8mG2QrL2vLSFOsqaqhdEh22uGrODHC7iH+3aPMyghWLAkARUPkRXjGRXryHtl8w8DRvQj
llGb0KUH6SqD65H0
''';
      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      expect(
        publicSubkey.fingerprint.toHexadecimal(),
        '8f1cb653b2c3a4808302b63b52c1ed36e9e22006',
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.elgamal);
      expect(publicSubkey.keyVersion, 4);
      expect(publicSubkey.keyStrength, 2048);
      expect(publicSubkey.isSubkey, isTrue);
    });

    test('NIST P-384 keys', () {
      const keyPacket = '''
BGc/+YkTBSuBBAAiAwMEd3FJXIrlQksBiwOLB+ksANWsTQzFNxqpxzjpglaDNKjgF/RXVXj9A6os
ao0WJtqkKFKZvkASvOCgOaBn3GDUZmF8GJwuuLNOci0JC/N+g5nFd/BeXNJNyECMIbllcLt9
''';
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final keyMaterial = publicKey.keyMaterial as ECPublicMaterial;
      expect(
        publicKey.fingerprint.toHexadecimal(),
        'a325107e66bcab3eea407550396ecb8bb86d1922',
      );
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(publicKey.keyVersion, 4);
      expect(publicKey.keyStrength, 384);
      expect(keyMaterial.curve, Ecc.secp384r1);

      const subkeyPacket = '''
BGc/+YkSBSuBBAAiAwME6+LPwcbdvoEdxPA2L002pKXp8Nt7PxIsjUegQRw2bTQXMlu5zplsUNpr
WJZ1W/iqLhmEH8eLONxcuzVEQMb3dCImxBzmL3Y5HxGGti81EsU7JBIZxHKhl85RY78HdHgCAwEJ
CQ==
''';
      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final subkeyMaterial = publicSubkey.keyMaterial as ECPublicMaterial;
      expect(
        publicSubkey.fingerprint.toHexadecimal(),
        'bd7133409a3ad7986fbae32a5a2990ce6bd63b20',
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(publicSubkey.keyVersion, 4);
      expect(publicSubkey.keyStrength, 384);
      expect(publicSubkey.isSubkey, isTrue);
      expect(subkeyMaterial.curve, Ecc.secp384r1);
    });

    test('Brainpool P-256 keys', () {
      const keyPacket = '''
BGc/+dATCSskAwMCCAEBBwIDBJ15ari0PCq317awmdNNIwz+yOZ18yUCg8LOAmYEaRAqAh1HmAnS
K5d4i1CX2M2/UKup7f/KD/o5Y6oid+VuTZQ=
''';
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final keyMaterial = publicKey.keyMaterial as ECPublicMaterial;
      expect(
        publicKey.fingerprint.toHexadecimal(),
        'cd1b5b14294f80be65cefbef9951219fc9de9578',
      );
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(publicKey.keyVersion, 4);
      expect(publicKey.keyStrength, 256);
      expect(keyMaterial.curve, Ecc.brainpoolP256r1);

      const subkeyPacket = '''
BGc/+dASCSskAwMCCAEBBwIDBGuDRKYwfAtThNOAM51Is4J1BYPN6qZCTN0c9ldSQzGSVO0lI/BV
2JJsuQqI0Pne08Y7og4bhyv9S+D+wcU8sv0DAQgH
''';
      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final subkeyMaterial = publicSubkey.keyMaterial as ECPublicMaterial;
      expect(
        publicSubkey.fingerprint.toHexadecimal(),
        'fda27358dac2b11fb5388cca65b53bd1aff05e06',
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(publicSubkey.keyVersion, 4);
      expect(publicSubkey.keyStrength, 256);
      expect(publicSubkey.isSubkey, isTrue);
      expect(subkeyMaterial.curve, Ecc.brainpoolP256r1);
    });

    test('Curve 25519 legacy keys', () {
      const keyPacket = 'BGc/+gYWCSsGAQQB2kcPAQEHQGUAHTxwcB6TD72goFQpLf3jAqdbm1cZwv1N2mjBffEg';
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(keyPacket),
      );
      final keyMaterial = publicKey.keyMaterial as ECPublicMaterial;
      expect(
        publicKey.fingerprint.toHexadecimal(),
        '1148b2a24f580977c27b26223ed475dd212d221e',
      );
      expect(publicKey.keyAlgorithm, KeyAlgorithm.eddsaLegacy);
      expect(publicKey.keyVersion, 4);
      expect(publicKey.keyStrength, 255);
      expect(keyMaterial.curve, Ecc.ed25519);

      const subkeyPacket = 'BGc/+gYSCisGAQQBl1UBBQEBB0AJwaWfEiJqlOIk/O9i2PMaDBmbRUOBHGQdFRPKbifpfwMBCAc=';
      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(subkeyPacket),
      );
      final subkeyMaterial = publicSubkey.keyMaterial as ECPublicMaterial;
      expect(
        publicSubkey.fingerprint.toHexadecimal(),
        '12ba12e01b12582680057e8b44d20d3a674af1a7',
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(publicSubkey.keyVersion, 4);
      expect(publicSubkey.keyStrength, 255);
      expect(publicSubkey.isSubkey, isTrue);
      expect(subkeyMaterial.curve, Ecc.curve25519);
    });

    test('Curve 25519 keys', () {
      const keyPacket = 'BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWj';
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(keyPacket),
      );
      expect(
        publicKey.fingerprint.toHexadecimal(),
        'cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9',
      );
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ed25519);
      expect(publicKey.keyVersion, 6);
      expect(publicKey.keyStrength, 255);

      const subkeyPacket = 'BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1';
      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(subkeyPacket),
      );
      expect(
        publicSubkey.fingerprint.toHexadecimal(),
        '12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885',
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.x25519);
      expect(publicSubkey.keyVersion, 6);
      expect(publicSubkey.keyStrength, 255);
      expect(publicSubkey.isSubkey, isTrue);
    });

    test('Curve 448 keys', () {
      const keyPacket = 'BmbzbxMcAAAAOclr6WO01hRcPLq6+/O0G+HA8hfV+fWyej4w7y9j6Im19Y5lOhbn99B0mZ0i6ggJLxcf/wPqwG3hAA==';
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(keyPacket),
      );
      expect(
        publicKey.fingerprint.toHexadecimal(),
        '3005ff8cc9384ac345005882c5419e988efdfcee6646b0ce4f627fa61b23dcf1',
      );
      expect(publicKey.keyAlgorithm, KeyAlgorithm.ed448);
      expect(publicKey.keyVersion, 6);
      expect(publicKey.keyStrength, 448);

      const subkeyPacket = 'BmbzbxMaAAAAOJa5nnjGcHsLaqmdVTiX+7/V12+ROn+wufLdRd1egnJCCGBhvN7XDPd50Em1ZtAbYgbCsR+C8zgZ';
      final publicSubkey = PublicSubkeyPacket.fromBytes(
        base64.decode(subkeyPacket),
      );
      expect(
        publicSubkey.fingerprint.toHexadecimal(),
        '6572e897cc45e44e3c707b88ac5a754b4e3372d47d122f22dbaaee139ac82c89',
      );
      expect(publicSubkey.keyAlgorithm, KeyAlgorithm.x448);
      expect(publicSubkey.keyVersion, 6);
      expect(publicSubkey.keyStrength, 448);
      expect(publicSubkey.isSubkey, isTrue);
    });
  });

  group('Secret key', () {
    const passphrase = 'password';

    test('RSA keys', () {
      final keyPacket = '''
BGc/4FEBCACZXe5kmfKWChtAGdoYRxRkEcfm0Ne431ovB4QS3zIOoclfyA7jgyq1UAhKbsYhZmTK
xx0FO5/HKOO2ojJU3AeKbLP+xhH8yVdEK5JiySvX/16Tz27d+r5WGLkjZMYZAxWW9hdfurajYp8v
cdACvErKMXShXUR9npCKH5O0QBagxMg6vczfJfNG1qWJ9aeFO7yffUt9n+39ru3Cc67EAp7m29Wo
wto15xmeXCPkYEgE+BM+86AHGqihOERjPCzWeFVLRuCwj2YjmZvtMh9A2gx5K6dMQ5viMDsTSoB0
DEZzvY+Q7gr7/qiWCpSfmy3gvmReOvMzk8uI7+Nt6vdJia4vABEBAAH+BwMCkDFoVUgR+jX/2wzp
aUM538tEPM92fd+PMCzwMVgu1DObhiVDyBSfLJDWsKPCT4dvE4gBK5exaYcVuLGzuI9AfBx2uDhp
0usI9AWQIQ/QqXEz9dwvLuI2RJzLHC0qarRhZo5H+ae5KskY+gBgdKNQ1o/wO1dTpgVSMhiUzRSn
MqD11MEk7geRh3MEFrf0XWjRykglV6Hs0a/LAYanBsjIAHVFMwQqxJJPtN/u2vkOW2cgplB96Bdz
+wu8jEd9LLDkZSS9AnI6TW1LA+QW1jrkKf86oUfOZ3aIBmw4h7kaVOH3lphe0ozNwWuErx/NjUVA
acTTLas2GERBZOKAefTfrcP7hFwWn6+x07G8EnusA0t6kx2H8m9d1lkJ+YwagxMEEA0txdbrZ6yp
4UzJs1ZrBEDhhE/HSiDJjd4sgtE0FE8BOr8kEA2o/iNo0PcllGm8lUOZzj0z4AUowYTYbYwmin5Z
HaWqfLqaXXzKUq+7UUQ47irgZtxB6WJG5ZjW2n2BYIOrqkcT0DBAaRhg4lDkEtw6fJyTq1luuWQT
0wd6B8y6ldepbequDv1+rU+fAgo9hyd3FplQzwFnxkN3XU7rjA9YF1T2jdy9s6M9QfEHypKFzlLx
p2UWHcmKp50EgN14eMa3QrNN2g/jfJq410QSEb12AVV/bwpLvlMbqvIpyur9qJIkeSoYKKlJUs6t
OOiW8nYJHx6Oh7gPHysqfoqUkavY+W9SFDcAb7ch81WfqzB30WufUI49ZiB9V/Zytrs7He4dyrgF
o430Mw9yVfhDxHUiPoNLBugkKEyNL/VOoPGMdgSW0gAdpqDQecyedjE7LAMnpWXb40R8TcnX7Y5/
HDDqkxYX2x6gJyijanX8RDqEh4YJZcIx7UdQhLgZ4Ec9aWMazAtViH4zljKpdiABYEdTgsLQ
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      expect(
        secretKey.fingerprint.toHexadecimal(),
        '5ccceda54f917089f8c488000532372a028f2ff5',
      );
      expect(secretKey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(secretKey.keyVersion, 4);
      expect(secretKey.keyStrength, 2048);
      expect(secretKey.isDecrypted, isTrue);

      final subkeyPacket = '''
BGc/4FEBCACUrspJcjpxuAKKF/2gPWJogkTuk+Ya+BUDjgPI3Cph8APkFfVct+NNwSW1xD6Bg/lG
SH0hedXUTDVyCIXd1PI8tWEjB41aRu2hVJ908UAo7KVmST3zNSRClNJPN0ff7KV67K6K3PcWi2Cz
V58NZSBK2kZqQpzQRCFHq8NYo6NQnJ7yhYxH3dfW7F0hVwMzcgw8SitNRW0vNlJDJQdAbveHh8w3
uZQ+tEAs7QsZVdVj2J7RFOOAD1J3NlnExE3mcawwPi2KLKv8lGzO0jLNPiEnKD64LbNE8QDr+r2b
R6Cx4/cEJ5qXuHTUESblPwkkPlW3wv2tDdRqQZKyGLOIKe0LABEBAAH+BwMCBDUxfK61uLj/E/nK
zXpSm0iwJUp8wrRjhyY5/2lFqY2gM9sj4366STySJliHR4qe7oS1ZZdRDz1bRN05SIKWdfoJZx+V
ExhLEsVgDIbEMo9gBbDlUV2hPHKjbskdcoE4SBXYFZurtj+aeeeTlQbIlwZxMJJGuXQDzgbYCnPZ
5sdQoHxnTF2LIsHYOGBdQIlL+InuHktk/x6rn6E4fZAo6xHFiTCNfWLVbx4qXpzWfST8QeF9oAvF
CRAxmKOv1gPi5xHryN7qIf8M1sWrLpQgdPBrXj9OQJXpf2z5jQtIzolQRpcCq0bwiMi5p+1cN1TN
PpZRoghf4JWc22s8QxcTsUCSkYzZ3OcHzQU2GSAaZQmyS6g1W2OBgG3sr0kCFSjtBx7RADWAvJzz
UPm7TBybibWviS2kG8bNM49nmw20V3B8CfzAhrtcX39Z0t+c4eU6lsI0ti+pL1TVbgFgYMYUxhjk
CZeW/2XWPeqNkd/RVwbOMlqQTYrgxkS80hgJm9GsAoTRLn6DFolo6l04/RF5DWZDDe4JVMzy/2Cq
aBVWzoU50W9+eLTs39MKkUSy7YLmQ3V8cAVjDhhtTCP0L0XJyDKnXdtQ8MUPMek9Uf8eZfUb6rLX
T7EHxw63dh/dScftNrEiM/4hhexXlpvz5cm07MevAI/lot7/k7WNRfFt3kEnL9snu/J1nwUBok4Q
lm7K/bsmeLzsLaiEXgRyeqCl5u/mqtyXTd0Igf7X39RBjk/EyURL6MhnHbpcUvZ2l8lEadN7B+gD
08qei/YvIFq7IP+rkPkYRVCe2+SBbEII4djEAQ4JJli2RyMUNGLdp8IMacU+HM+hYIVMLdszkPj9
67DCKbCQHpre89JE183ERftUN+19Mzxx8UQLfAg5XhpQ8xO3ziubO2aID1HiFmRMlQNJm+/d
''';
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      expect(
        secretSubkey.fingerprint.toHexadecimal(),
        '79fb82ac1204bdc854e87364316ef1539787254f',
      );
      expect(secretSubkey.keyAlgorithm, KeyAlgorithm.rsaEncryptSign);
      expect(secretSubkey.keyVersion, 4);
      expect(secretSubkey.keyStrength, 2048);
      expect(secretSubkey.isDecrypted, isTrue);
      expect(secretSubkey.isSubkey, isTrue);
    });

    test('DSA & ElGamal keys', () {
      final keyPacket = '''
BGc/4H8RCAD3gDG7FSfKWRy4/gNe0sgYYgZ4zAFZTLWneObcLYpY+kmwufUIrAG0iWt8kzLbiLon
A1B7ss041yCqJgTHFcttH5nFG/q25MT+xq+V55TRZGzaD6Gy65E++CuS0m3gJmLH14bX6++5Evtc
/bkOTGgIfRGfEH8pL1ePc9ev1EFtmOYgZkX0a7oM8TiNKVNnUKwhuBi7pbC6OEOuDL1HmbsAHIE4
n6mMs3HzJCNEAkvHNcQGZNdn8SD3d3ukljOq03ko+tC2Orys1AwiZokL10EOiZYQZ55KAOFXM/Hu
ayVQ8xR9Zgg8i+8HdjvAzaifH6ThOMDE2I80Yp/jllG/PBBvAQD3msVRxzpaT3WiMeopZAOM+jeF
xwy8bG0W+BOJwn9BjQgAzFLIFwHauCi4ooI0JsndyKE6TCexzA46r0nA/1BcNpRtUlhLsEwJ0app
PkCufixLL0RYKTnxgfrAbxR+mrIPla1djnNysoYj8NfDms6aIoxKzT7gN9WWwgwaTSo7lesJ8gZ6
aZLt1kBEHj+72MUb5Jgynzjd6HA8FwQvXIUaQl0HDmYByzr/hBtVzrog5fSR/jTXX/ZbTivqgHV1
JzT0NlTBrFEGuIFRj54JvEaiYtE/Z/lWkIRmcrAwaSCeutF4w4Xv9BhhGdRtLo2AJCQeR26sOk1k
xihdes4zBrhI+e0wrAG7G4cNOtS090O8tvIWlxlrJXyYmpZR6zHxBYbBIQf+Lk0Jou8CnR1S8oeN
EdBfeuboNWTDVz93iSEBHkSIFfwt07IvHra0wKKkYwX/p8zWyw/Me2e1xtRommFSpIqW9pWimT4b
kTtPqXAwRD4WhfVOnGxzXsXaYSWIf4sr9GusPJTsAi2cdtKTDzXFWDpJDvJ24bPa/P4oEiECno2s
2KkfQqWZbSRbOsDX8/Mdz58XzOWOv3j0A1oLLZFK+a0LiJso31S0jG71IiMFlaXWNQD025UV6Oup
lqe/P6qdArk72Qaum4QBsFfTLyKw12JQc9HPfV4Fst0sSbky+0QqqVfegHnvcnJBrjZ2pahL+EWU
LYR9lty0LinZ0v6+5HtwDP4HAwJJoSaWNPq4ev84yDB8BqwxkAVvV7PKMkzyYAGDBPNp8lr3o8hg
rG84tNOSruda3xGptnE9aBQ+ZmibNZata3DR3NWfDY1R+WVSw9D3hybj
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      expect(
        secretKey.fingerprint.toHexadecimal(),
        '9a83344a3711864c1f502094ba727d0f6b50c281',
      );
      expect(secretKey.keyAlgorithm, KeyAlgorithm.dsa);
      expect(secretKey.keyVersion, 4);
      expect(secretKey.keyStrength, 2048);
      expect(secretKey.isDecrypted, isTrue);

      final subkeyPacket = '''
BGc/4H8QCACv2nUuptC3DfhXtkI3H825wX+OwZzwOP8MG/JNUut/RoxFDXnld1S/GVz/dDBXs+cM
QY4M9Fe2KfsGbNVeOId8eBENIFE7DBH6Qigh8WkBUueV6qPeFkWVj7u72TwRPjR3A6uAwLv/ZrMZ
JWqD52tDr2YDv8e5LlS8uzVmTYo9nU8ohn3n6KyKNarEhpuXHqo3SHt4H7601Nr3TqdRU5ZWW1F6
QEjj0Mj1st7ctPkMjj4R5IzfRZHyDQIrJA5Vp76cZ+oXZFIgrkWwJ//HZ/txc2PGLYYf6OCgTZRF
Rh720ETDf4arK1FheJ2qVad4YX+21PvdzU8DeIn4McO8QyM7AAMFB/9RdNV1kNfAl7LPOUp46sO/
97esXDT5DfLcBgV+bdUGuQonASsKk53phnwp1mLhfRe1TldkoWpxkOOZAHXDdr+hbSp+UNimK9Bs
X/jCYcQr0Il5Agq8F8Idxrwv2ftlFVAsuDrwyzhGFHFC5mXPeloDG1aF8cyWKXbONM3DzBwISW4p
wKXXYZqqiDgmlQ/anjEExZqmSs6+sqWpl45iAsAB/jYvzuBl06pJFxFJo7TwNAKhgTFHMGlHXjl/
JCbd1xv8mG2QrL2vLSFOsqaqhdEh22uGrODHC7iH+3aPMyghWLAkARUPkRXjGRXryHtl8w8DRvQj
llGb0KUH6SqD65H0/gcDAi1ba0lMwyKy/9drqpArIcD64YJ6D9a2xugmzyycAWopnNcQOf9ABltG
PFnM3cGVkY28QyU3/x+/fjvvX6AsmGDqZqzYaXjre00dg3c4bBNcJD1e2fEbY9C0Hw==
''';
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      expect(
        secretSubkey.fingerprint.toHexadecimal(),
        '8f1cb653b2c3a4808302b63b52c1ed36e9e22006',
      );
      expect(secretSubkey.keyAlgorithm, KeyAlgorithm.elgamal);
      expect(secretSubkey.keyVersion, 4);
      expect(secretSubkey.keyStrength, 2048);
      expect(secretSubkey.isDecrypted, isTrue);
      expect(secretSubkey.isSubkey, isTrue);
    });

    test('NIST P-384 keys', () {
      final keyPacket = '''
BGc/+YkTBSuBBAAiAwMEd3FJXIrlQksBiwOLB+ksANWsTQzFNxqpxzjpglaDNKjgF/RXVXj9A6os
ao0WJtqkKFKZvkASvOCgOaBn3GDUZmF8GJwuuLNOci0JC/N+g5nFd/BeXNJNyECMIbllcLt9/gcD
AibS8+RBYAf4/xdsEEtrOuKrD/gnBMI2OCJu1K3bDCZcPc/vgzHCB9Kb1H07yXVqgtKEaFzFBXuH
CD71iViIpDvb++MjKPYY4hHkxRVTvFUeAUldfZ/ryBE7P3L66CRS
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      final keyMaterial = secretKey.keyMaterial as ECPublicMaterial;
      expect(
        secretKey.fingerprint.toHexadecimal(),
        'a325107e66bcab3eea407550396ecb8bb86d1922',
      );
      expect(secretKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(secretKey.keyVersion, 4);
      expect(secretKey.keyStrength, 384);
      expect(secretKey.isDecrypted, isTrue);
      expect(keyMaterial.curve, Ecc.secp384r1);

      final subkeyPacket = '''
BGc/+YkSBSuBBAAiAwME6+LPwcbdvoEdxPA2L002pKXp8Nt7PxIsjUegQRw2bTQXMlu5zplsUNpr
WJZ1W/iqLhmEH8eLONxcuzVEQMb3dCImxBzmL3Y5HxGGti81EsU7JBIZxHKhl85RY78HdHgCAwEJ
Cf4HAwJi7cDpuChI6f9Q43Dx+3m60mXsaALEN2hfX5+bTxBAbp6yK6Qn95plMof6qGO6jqFD0Bzr
vXylI2X9iKleGoFNlyGtZiThWYmH+9xWNkQ/Lrekb5HxplhniQvxEJ41nQ==
''';
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      final subkeyMaterial = secretSubkey.keyMaterial as ECPublicMaterial;
      expect(
        secretSubkey.fingerprint.toHexadecimal(),
        'bd7133409a3ad7986fbae32a5a2990ce6bd63b20',
      );
      expect(secretSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(secretSubkey.keyVersion, 4);
      expect(secretSubkey.keyStrength, 384);
      expect(secretSubkey.isDecrypted, isTrue);
      expect(secretSubkey.isSubkey, isTrue);
      expect(subkeyMaterial.curve, Ecc.secp384r1);
    });

    test('Brainpool P-256 keys', () {
      final keyPacket = '''
BGc/+dATCSskAwMCCAEBBwIDBJ15ari0PCq317awmdNNIwz+yOZ18yUCg8LOAmYEaRAqAh1HmAnS
K5d4i1CX2M2/UKup7f/KD/o5Y6oid+VuTZT+BwMCatDpkioZEvn/eKkvTKbtGeDlyAyJaMjBhXV4
HS1pjTIMcS0XPyKav9+v5BqZmiZq09KfI3JUV+Ump2JUP7bKfMZj83NW1VDg2NiNXKcs9A==
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      final keyMaterial = secretKey.keyMaterial as ECPublicMaterial;
      expect(
        secretKey.fingerprint.toHexadecimal(),
        'cd1b5b14294f80be65cefbef9951219fc9de9578',
      );
      expect(secretKey.keyAlgorithm, KeyAlgorithm.ecdsa);
      expect(secretKey.keyVersion, 4);
      expect(secretKey.keyStrength, 256);
      expect(secretKey.isDecrypted, isTrue);
      expect(keyMaterial.curve, Ecc.brainpoolP256r1);

      final subkeyPacket = '''
BGc/+dASCSskAwMCCAEBBwIDBGuDRKYwfAtThNOAM51Is4J1BYPN6qZCTN0c9ldSQzGSVO0lI/BV
2JJsuQqI0Pne08Y7og4bhyv9S+D+wcU8sv0DAQgH/gcDAuO38MdHOYf2/8rps/QpKMK0ct6VeR8R
VNeB/QxOOoqo0SfMe61feVs/OVpmYKiKUK06YTzL4L4h4j1UlntEFqbWcqV0M0X9zuGGWHMMbZs=
''';
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      final subkeyMaterial = secretSubkey.keyMaterial as ECPublicMaterial;
      expect(
        secretSubkey.fingerprint.toHexadecimal(),
        'fda27358dac2b11fb5388cca65b53bd1aff05e06',
      );
      expect(secretSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(secretSubkey.keyVersion, 4);
      expect(secretSubkey.keyStrength, 256);
      expect(secretSubkey.isDecrypted, isTrue);
      expect(secretSubkey.isSubkey, isTrue);
      expect(subkeyMaterial.curve, Ecc.brainpoolP256r1);
    });

    test('Curve 25519 legacy keys', () {
      final keyPacket = '''
BGc/+gYWCSsGAQQB2kcPAQEHQGUAHTxwcB6TD72goFQpLf3jAqdbm1cZwv1N2mjBffEg/gcDAjRx
sogPOLUK/7mdbYS93x93u4Hvk7ELyLfD0bpBQCsPjGtcoA+mrp4vg+cm/evYvQd74FE+BIudfbrB
STrxtvZu+g7Sf0mBxv0WAszjy6I=
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      final keyMaterial = secretKey.keyMaterial as ECPublicMaterial;
      expect(
        secretKey.fingerprint.toHexadecimal(),
        '1148b2a24f580977c27b26223ed475dd212d221e',
      );
      expect(secretKey.keyAlgorithm, KeyAlgorithm.eddsaLegacy);
      expect(secretKey.keyVersion, 4);
      expect(secretKey.keyStrength, 255);
      expect(secretKey.isDecrypted, isTrue);
      expect(keyMaterial.curve, Ecc.ed25519);

      final subkeyPacket = '''
BGc/+gYSCisGAQQBl1UBBQEBB0AJwaWfEiJqlOIk/O9i2PMaDBmbRUOBHGQdFRPKbifpfwMBCAf+
BwMCw5mADNvfWY3/dQSVZmOCFBZB0xErKUmpHmTXDX5JmzhanhYOnssKCuiJ+Bt2N3logFkur/VK
gWiiTYzGt55CPH+6z9IdUnM/22Y2nOVfXg==
''';
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      final subkeyMaterial = secretSubkey.keyMaterial as ECPublicMaterial;
      expect(
        secretSubkey.fingerprint.toHexadecimal(),
        '12ba12e01b12582680057e8b44d20d3a674af1a7',
      );
      expect(secretSubkey.keyAlgorithm, KeyAlgorithm.ecdh);
      expect(secretSubkey.keyVersion, 4);
      expect(secretSubkey.keyStrength, 255);
      expect(secretSubkey.isDecrypted, isTrue);
      expect(secretSubkey.isSubkey, isTrue);
      expect(subkeyMaterial.curve, Ecc.curve25519);
    });

    test('Curve 25519 keys', () {
      final passphrase = 'correct horse battery staple';
      final keyPacket = '''
BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWj/SYJAhQEXW/XHJ4JbR62
kXtubh7srgEEFbSoqSdPq+Yy+HWnBlkgIXglj6SE2Isn8iDj0t4CA8oPH+7La3dTgePi2bFIXCIz
jKVR4JomPyLrSZLpZ3qAWA==
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          keyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      expect(
        secretKey.fingerprint.toHexadecimal(),
        'cb186c4f0609a697e4d52dfa6c722b0c1f1e27c18a56708f6525ec27bad9acc9',
      );
      expect(secretKey.keyAlgorithm, KeyAlgorithm.ed25519);
      expect(secretKey.keyVersion, 6);
      expect(secretKey.keyStrength, 255);
      expect(secretKey.isDecrypted, isTrue);

      final subkeyPacket = '''
BmOHf+MZAAAAIIaTJINn+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1/SYJAhQEDmGEaCnahpq+
DqYVRdwUzAEEFS4Typ/05yT7HC6x34YCCUGvktXKv+W6nfHFC8dcVKOMDaFpd+g3rFQZF0MQcjr6
568qNVG/mgDGC7t4mlpc2A==
''';
      final secretSubkey = SecretSubkeyPacket.fromBytes(
        base64.decode(
          subkeyPacket.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      ).decrypt(passphrase);
      expect(
        secretSubkey.fingerprint.toHexadecimal(),
        '12c83f1e706f6308fe151a417743a1f033790e93e9978488d1db378da9930885',
      );
      expect(secretSubkey.keyAlgorithm, KeyAlgorithm.x25519);
      expect(secretSubkey.keyVersion, 6);
      expect(secretSubkey.keyStrength, 255);
      expect(secretSubkey.isDecrypted, isTrue);
      expect(secretSubkey.isSubkey, isTrue);
    });

    test('Curve 448 keys', () {});
  });
}
