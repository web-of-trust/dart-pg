import 'dart:convert';

import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/openpgp.dart';
import 'package:dart_pg/src/packet/base.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  const literalText = 'Hello World :)';

  group('Sign', () {
    test('with key Bob', () {
      final literalMessage = OpenPGP.sign(
        OpenPGP.createLiteralMessage(literalText.toBytes()),
        [OpenPGP.readPrivateKey(bobPrivateKey)],
      );
      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(bobPublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'fbfcc82a015e7330');
      }
    });

    test('detached with key Bob', () {
      final signature = OpenPGP.signDetached(
        OpenPGP.createLiteralMessage(literalText.toBytes()),
        [OpenPGP.readPrivateKey(bobPrivateKey)],
      );

      var verifications = signature.verify(
        [OpenPGP.readPublicKey(bobPublicKey)],
        LiteralDataPacket.fromText(literalText),
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'fbfcc82a015e7330');
      }

      verifications = signature.verifyCleartext(
        [OpenPGP.readPublicKey(bobPublicKey)],
        OpenPGP.createCleartextMessage(literalText),
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'fbfcc82a015e7330');
      }
    });

    test('with key Alice', () {
      final literalMessage = OpenPGP.sign(
        OpenPGP.createLiteralMessage(literalText.toBytes()),
        [OpenPGP.readPrivateKey(alicePrivateKey)],
      );
      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(alicePublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'f231550c4f47e38e');
      }
    });

    test('detached with key Alice', () {
      final signature = OpenPGP.signDetached(
        OpenPGP.createLiteralMessage(literalText.toBytes()),
        [OpenPGP.readPrivateKey(alicePrivateKey)],
      );

      var verifications = signature.verify(
        [OpenPGP.readPublicKey(alicePublicKey)],
        LiteralDataPacket.fromText(literalText),
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'f231550c4f47e38e');
      }

      verifications = signature.verifyCleartext(
        [OpenPGP.readPublicKey(alicePublicKey)],
        OpenPGP.createCleartextMessage(literalText),
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'f231550c4f47e38e');
      }
    });

    test('with key from RFC9580', () {
      final literalMessage = OpenPGP.sign(
        OpenPGP.createLiteralMessage(literalText.toBytes()),
        [OpenPGP.readPrivateKey(rfc9580PrivateKey)],
      );
      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(rfc9580PublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'cb186c4f0609a697');
      }
    });

    test('detached with key from RFC9580', () {
      final signature = OpenPGP.signDetached(
        OpenPGP.createLiteralMessage(literalText.toBytes()),
        [OpenPGP.readPrivateKey(rfc9580PrivateKey)],
      );

      var verifications = signature.verify(
        [OpenPGP.readPublicKey(rfc9580PublicKey)],
        LiteralDataPacket.fromText(literalText),
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'cb186c4f0609a697');
      }

      verifications = signature.verifyCleartext(
        [OpenPGP.readPublicKey(rfc9580PublicKey)],
        OpenPGP.createCleartextMessage(literalText),
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'cb186c4f0609a697');
      }
    });
  });

  group('Sign & encrypt', () {});

  group('Decrypt & verify', () {
    test('with key Bob', () {
      const message = '''
-----BEGIN PGP MESSAGE-----

wcDMA3wvqk35PDeyAQv+M1BxrFVRm72/QLb+LGb4+OcxJ3NEJl+UASFzcbpA
OBdxcbU+lOKyN2sGWBh8D/ES/iv7dhmG71NG1dhklxbReM0VPQaaVM/l+s1S
YjxFa9JIl9IUbMFknIJFRT+PTpe3xhHWtsKy/3oiJgbksqOnQJXCH4ZtPuo9
GqEcCtrm3pCMJiQFamB6mhn251t+9SiYb4Hw5Vo6nTJsenb2zosZh66wKj3Y
HmagIDS9LdMSW2rFwI72Nnj1wdyUXMqiUbilDOhpoTuSJFg6JCoMNCwIuGOF
W+BWmm1zuaV6qkQ40nmapBj6NTRm7bFqj5vxTrCLii2z7gZRzXn6HGx9qXw3
UhLnuzNJoXFuzp9pul2bBVkkuusWJ+k7QWoqBSdJuZeOgJdK4qlC7AKE51e7
o+y09JtVH8EdShGwDI8OL7Dbxkcwv5zOlntnD7d14OnMRIjkw1EwmSsaDUkH
v8z2qcO866ddqbA5x4H90XxKh1VxDTS0h1qvg/gY2QfVCPPFRdFL0sGKAW3H
LmmtucpQDkMRZJpqwDKJCugYeBtGKaoSlQ1f+pxC5qlZu37SdCr7OP1/P9Sc
p0g3phRw4QbPHJ2xu/0oXpucKwEGbPhAnZwHwRNNr+1dJJSPJ0lqvYPHwDWn
L5Jivev8hQ5MnkBKRg/ITyGxbsln42VLuhu3C+o7dm1J2fw4S9NKh0l4GLBJ
nfk0eUJ8qH8SKta85TYoMOpOFSJzSMKDssq5RfWQ+q7MWu0UxpOxBrbRfAm5
D3IdtEm9DmyAhAD5HG6bo1TTMQHk/QuKF8VOtK/lMnPDEPbFjIRbD7NYKg0S
ay7sHWVOslk+KEpytmUT4uBrjFVPPdWjL3B28/0zaf/KI6TWsQ7v5diqT59S
/PkWPbNISiumTlUwnSwzEBE3lxNMpHzePSZwzJRHh+Dq0DhnmZYsglxgHsRj
gd3eqxVtzM6fbG0vG3QHM3canOpmYMZ+rHfBouNeb78BKLgHLnCHCc/wgK+1
jzVzBZyzb3Su1t8MP349WyKDk3m/Z/Yy9tJTMCKI0VHgL74xhzrrUT5Iwsxr
XJ0ehIL1yIZH6+794dI13in7cxZataf80Apd2e8taXortOTLFP+z/0zQT8Hf
cSjtDCQZckGmNw4GiEXWpE2XSrDktiHSlLxOSTtUQsLzJfBftqFlC/ieLonO
ww9zG0LKI4f+mXSsBkTaQBwVsdHYfhAC2R1gGWTbjvNDScaTsbaNlo8LYJ47
lFiOpCG/SDaD4bl7BYYf9o6c6Gs9vKf9mShmWUO0tg2NDlFAzdQTBOzaxw==
=BADY
-----END PGP MESSAGE-----
''';
      const privateKey = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: Bob's OpenPGP Transferable Secret Key

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
=miES
-----END PGP PRIVATE KEY BLOCK-----
''';
      const publicKey = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: Bob's OpenPGP certificate

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
NEJd3XZRzaXZE2aAMQ==
=NXei
-----END PGP PUBLIC KEY BLOCK-----
''';

      final literalMessage = OpenPGP.decryptMessage(
        message,
        decryptionKeys: [OpenPGP.readPrivateKey(privateKey)],
      );
      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(publicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'fbfcc82a015e7330');
      }
    });

    test('with key Carol', () {
      const message = '''
-----BEGIN PGP MESSAGE-----

wcDMA3wvqk35PDeyAQv+P3jUz8+V8lGGZNr9BtbhbQJqzq29wa6U5dH4H/Qdqp60
0AZ+dojl4G83PaBWxxNNWMvmdck15SCELb9e6JJoacMRn6cL9uuBz5v4Orjn3O1N
a735zZyS04bGiTKU0NUjUlxUYiLXfAepPThZtthMnOfUUW3a7nBKUuuKzqlu7nhw
BKCf58rsZZFXiXDYUxrGR/muoglxfb8KXixd/ZlhKgoYTgZYJ6vpYh3jZMSni/wr
49UOQx+H2Z6QEKaYoYu2FQoHbD1iNGxdI7a9xLXffnu6VO63Vq/ohN0/uXj6OBGU
r5GCspM3LPjAWevp+AxGdRa5RxQFbD6yODeI2coYZwUnqE1DejOEf9gRY2dDG9e2
1poMUWBFT6rTGjisEOPZwZnANMSBfh8dHeMsE5cYO/BV14TFqwl7oc7LTH4VVG6I
llknMul0jDM71hBtbZcGVTz8xrdD165EmxxMS/FEBKZg15thiwkZwE2nMSQAtOhd
h+46EmEhJnW8GorsP4nm0sBNAXGupU8fjiE2iDjlGwe2ZU30G4jFOCTsojRC71m8
g9S2yV9Bj3Dp+RGUgMiFOpdel00prWgsGGPAUTHYK/YeVYgiQkGu2bQbrImmI4nd
atMkRpD4VvoxVp4zKijUaBY9rYFOfytbLUtYqMjG6szoMUHCWYCLQgs4DKd794dS
waprJuJ73JBJYhZiYqm252qg0kZE1nlTxsTJpz1Ld0ZvF6S48JJyQz/YutMjlhrL
N9rHEwCTBV1djiA4b8oqdamwFTkU2ge0OorUMbi/bEvvYQkLO35G/hc4jRZVaiJO
wqP2oIPIsEeuMG40kub7RpJWnidJMnOoG7ZScRqbwkECF89DN4sYYREJkaaHFr8=
=JDtL
-----END PGP MESSAGE-----
''';
      const privateKey = '''
-----BEGIN PGP PRIVATE KEY BLOCK-----
Comment: Bob's OpenPGP Transferable Secret Key

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
=miES
-----END PGP PRIVATE KEY BLOCK-----
''';
      const publicKey = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=pa/S
-----END PGP PUBLIC KEY BLOCK-----
''';

      final literalMessage = OpenPGP.decryptMessage(
        message,
        decryptionKeys: [OpenPGP.readPrivateKey(privateKey)],
      );
      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(publicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), '9ba789dc76d6849a');
      }
    });

    test('with key Alice', () {
      const message = '''
-----BEGIN PGP MESSAGE-----

wcDMA3wvqk35PDeyAQv+N2n5QLKCt+0mZZXMXTJEABvg0VlIkigYesz6FNy/
m9eLBlevQqtCjXZGMVDATHTkmKvzMTYfs+66qT37YRFiIGOd1NbwcDGXz2sQ
/lD1hwFlpWCmrqrZnG9abaa/OLRWFiXdCXFgaHNOZXnYM+/Dwdgt4bNCbW2w
Vkd/cPWv+ZcHCOyDl5fw09syOxvYzUCTB+KOZVsXI2StZpPCrRoF8zbLoy6p
q3pLEQEYi65iHbQ07DSgXS/1XJZ8ktKDvPRYysR7htwFU9KUaqDUUoDd7/sM
iz6NoV43yubfTAVVg3puLOyy9O1g/iQtCy7+Wa98YnyF5i9V7rFfIgERbcOz
xktONm6srYLq7SVIe2nWIcAFtbKjpwTXUyfKxkHR9zUHg+I/FuNtZbPtBwja
hKpvFo8Y6zotJgJA7Q6uWhWTYCmWqzc0VO4M5ZoZmA+mG3/QLnmtkBLTr7mb
tTwD42xn4np0uTqCdO5ypbEgoYEsksvpYSxq9t4pAzY9NdxXLOjX0sBLAcH9
PHyPS3SQOHbqRFjaauY2lpATSLKspX1uvxiQU9P70ezSnMb3T4j0fVjRO7Wc
s/QdUMWuRFJtVZfld81Z/d7vPxwdCgnxmY+6UC/B7ilBfhaiFFhfVhRGg4wP
CNtkYfJ/8p0BPpysdSBiunk+Pbkm6p5zTyszFznC/RXprnEDOYLerAvuFxnC
6LjoOXOUhAsOaRM8HRqyeD4ilAotXR+FPzAHk8aGJ3SiDG9GUHve/JaIbZWm
GVnPCFp8hpLt6mAmH4VonnmYVhrkKReT2yfGgHhd5AL8bIa/bRbwcUatUPDG
xBfiBCSwAsSjvat9sW5YOIcqo6hUMnY804L61RklAJn93ohVOt0N
=Bbti
-----END PGP MESSAGE-----
''';
      final literalMessage = OpenPGP.decryptMessage(
        message,
        decryptionKeys: [OpenPGP.readPrivateKey(bobPrivateKey)],
      );
      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(alicePublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'f231550c4f47e38e');
      }
    });

    test('with key Alice and Bob', () {
      const message = '''
-----BEGIN PGP MESSAGE-----

wcDMA3wvqk35PDeyAQwAiXlhEhgJ6ptfYt3A/kkMMUFZIqDsXwQJ5xHLQLKU
uRXiIv7LcsezCNNUOAQaEP2fiM90qCEVNGpTDLohoH9eyINSFUSleFEbesaA
+gjOyxavxgcOiJbBZXvAeE/YJXwOpLj4otAU/GMPYQIY1CRXbgL29cEGWcuA
Bs4Ioc0FoqDUmBbDinHPo7JlllEVXaIkchW/52GwidEMJMNOpkyJ1mFzemb5
o+hO3+8PaeWtnRyXe911GhCKslYfrUHgyimPBZiCF6tUxsZ0YhGWkgohQFWD
bgBa1hSeHt2ERvN2aU5qmRLoSkOT4gTKClKEfMQ47+MlINvtpdAsiwiC5q6n
uDpK+qQKaD8GLWCBn90nxCnkzTJanJzit9Ce4q0porpOVlUXMHq2KUOi91cz
QygoHlJvOTcqCR2KyQ1L25UuUUmzbklJ/R2UkX3uQG8wMlb10lWbEhxBytnM
wCe0LDVUzrT7BVs0QalEyH/PlJXLyMJ07Y1waegSQq3INw4gSh+70sJWAUvN
KN9wWFfbX1pOzZGJyhb1lQsCFcj7Yp4o6UPG1c97TEI9RL+SockgKQk+AGKo
YmHzM8xgtETw7Taps7wLQb52oeIVNbkhYZy+7HEPo8KzTUaf95LBkQeL/TfL
nGbnTFY6wWGoOcdTnRmt+anvAmvcvZ2nmK7JlX3M1Kv/vui283NliUAsptJx
YinNvAfhe8hxpObr/iFD0dcFGu8muXgqTohtJMt0izxjTqdaAMuI9rPXt+Mb
DfJN8VlJ0ghPbpbqMUDz3exckvcCXIevfLq+9kmKzKi83Dt5cQNNHoZ5gUs6
+JGhpkx2TISnfIDXS2SDIiU+PwQDTpJTvfqsvV5+EmnLdB7X6ZapxB2eVacq
LRps9j6dhiAlHQpPZ36dth89EIsXfus4iWMA74URmOfa5Rq6sqyX2LAv0trQ
MajDkzGv5FKfBkgPoqfC3rJm88RLnIszdkWe6XsMYl+9lUnKXcMENGZSTsoe
hW79Xuc93ZfYcsO+r+RalM9colA5cvvPk6cTdtlGzBqBNTlOtEOdJeK487cV
GWrXeqU0sT901yr0O+JameTUYwPeHNiDigeVOr/vb/ogozwyPxq8JZZgdfQc
fQ8MNbFJze7r447BRM9WvyDGnVZgaj1IPz1+v+h97c4qSaDIfe5+QwdiNa4K
Lho0u9lfRTIRGL1efK8A+eVU4lfPZmZkzxbe67rmMUevGKo4kRypcXyknLSv
MSZVSMKpxAI6cJKCrC/i/j7mX5txLIrG/ufZpbR38XisPwE8asqi2eFwVynn
CstQEiZNOIjd0d+W9cN37TGsWdAyWwv2LTawjzwAhRYvs24/FgGYJmlqFy7O
wkzWnB5x/XqdMqWC1lYexLIPTqx9wkYGqAx+QI4vh8xysmBb9CJpvQkkXwkp
IARIvbdAzc++tARNhXUPPxjeUybMxmSH+SWGU/RqMxo8jaDp7YKhoNPv4B6v
lGTgNJurYorPkcWEPFRrJqtNvWxM9tqQhljCXQUvNniSdkwLZJqaxxWrwuPe
vMq9yq4ffP8QAc1kwjaK9aJ/J45fPw==
=M/i3
-----END PGP MESSAGE-----
''';

      final literalMessage = OpenPGP.decryptMessage(
        message,
        decryptionKeys: [OpenPGP.readPrivateKey(bobPrivateKey)],
      );

      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [
          OpenPGP.readPublicKey(alicePublicKey),
          OpenPGP.readPublicKey(bobPublicKey),
        ],
      ).toList();
      expect(verifications.length, 2);
      expect(verifications[0].isVerified, isTrue);
      expect(verifications[1].isVerified, isTrue);
      expect(verifications[0].keyID.toHexadecimal(), 'f231550c4f47e38e');
      expect(verifications[1].keyID.toHexadecimal(), 'fbfcc82a015e7330');
    });
  });
}
