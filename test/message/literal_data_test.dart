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

  group('Sign & encrypt', () {
    final literalData = Helper.randomBytes(1024);
    test('from Bob to Alice', () {
      final encrytpedMessage = OpenPGP.encryptBinaryData(
        literalData,
        encryptionKeys: [OpenPGP.readPublicKey(bobPublicKey)],
        signingKeys: [OpenPGP.readPrivateKey(alicePrivateKey)],
      );
      final literalMessage = OpenPGP.decryptMessage(
        encrytpedMessage.armor(),
        decryptionKeys: [OpenPGP.readPrivateKey(bobPrivateKey)],
      );
      expect(literalMessage.literalData.binary, equals(literalData));

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(bobPublicKey)],
      );
      expect(verifications.first.isVerified, isTrue);
      expect(verifications.first.keyID.toHexadecimal(), 'f231550c4f47e38e');
    });

    test('from Alice to Bob', () {
      final encrytpedMessage = OpenPGP.encryptBinaryData(
        literalData,
        encryptionKeys: [OpenPGP.readPublicKey(alicePublicKey)],
        signingKeys: [OpenPGP.readPrivateKey(bobPrivateKey)],
      );
      final literalMessage = OpenPGP.decryptMessage(
        encrytpedMessage.armor(),
        decryptionKeys: [OpenPGP.readPrivateKey(alicePrivateKey)],
      );
      expect(literalMessage.literalData.binary, equals(literalData));

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(bobPublicKey)],
      );
      expect(verifications.first.isVerified, isTrue);
      expect(verifications.first.keyID.toHexadecimal(), 'fbfcc82a015e7330');
    });

    test('from Alice to rfc9580', () {
      final encrytpedMessage = OpenPGP.encryptBinaryData(
        literalData,
        encryptionKeys: [OpenPGP.readPublicKey(rfc9580PublicKey)],
        signingKeys: [OpenPGP.readPrivateKey(alicePrivateKey)],
      );
      final literalMessage = OpenPGP.decryptMessage(
        encrytpedMessage.armor(),
        decryptionKeys: [OpenPGP.readPrivateKey(rfc9580PrivateKey)],
      );
      expect(literalMessage.literalData.binary, equals(literalData));

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(alicePublicKey)],
      );
      expect(verifications.first.isVerified, isTrue);
      expect(verifications.first.keyID.toHexadecimal(), 'f231550c4f47e38e');
    });

    test('from rfc9580 to Alice', () {
      final encrytpedMessage = OpenPGP.encryptBinaryData(
        literalData,
        encryptionKeys: [OpenPGP.readPublicKey(alicePublicKey)],
        signingKeys: [OpenPGP.readPrivateKey(rfc9580PrivateKey)],
      );
      final literalMessage = OpenPGP.decryptMessage(
        encrytpedMessage.armor(),
        decryptionKeys: [OpenPGP.readPrivateKey(alicePrivateKey)],
      );
      expect(literalMessage.literalData.binary, equals(literalData));

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(rfc9580PublicKey)],
      );
      expect(verifications.first.isVerified, isTrue);
      expect(verifications.first.keyID.toHexadecimal(), 'cb186c4f0609a697');
    });
  });

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
      final literalMessage = OpenPGP.decryptMessage(
        message,
        decryptionKeys: [OpenPGP.readPrivateKey(bobPrivateKey)],
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
      final literalMessage = OpenPGP.decryptMessage(
        message,
        decryptionKeys: [OpenPGP.readPrivateKey(bobPrivateKey)],
      );
      expect(utf8.decode(literalMessage.literalData.binary), literalText);

      final verifications = literalMessage.verify(
        [OpenPGP.readPublicKey(carolPublicKey)],
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
