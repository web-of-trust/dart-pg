import 'dart:convert';
import 'dart:typed_data';

import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/enum/signature_type.dart';
import 'package:dart_pg/src/packet/base_packet.dart';
import 'package:dart_pg/src/packet/subpacket_reader.dart';
import 'package:test/test.dart';

void main() {
  group('Subpacket', () {
    test('Reader', () {
      final initSubpackets = SignatureSubpacketType.values
          .map(
            (type) => SignatureSubpacket(type, Helper.randomBytes(100)),
          )
          .toList();
      final bytes = Uint8List.fromList(
        initSubpackets
            .map(
              (subpacket) => subpacket.encode(),
            )
            .expand((byte) => byte)
            .toList(),
      );
      final subpackets = <SignatureSubpacket>[];
      var offset = 0;
      while (offset < bytes.length) {
        final reader = SubpacketReader.read(bytes, offset);
        offset = reader.offset;
        final data = reader.data;
        if (data.isNotEmpty) {
          final critical = ((reader.type & 0x80) != 0);
          final type = SignatureSubpacketType.values.firstWhere(
            (type) => type.value == (reader.type & 0x7f),
          );
          subpackets.add(SignatureSubpacket(
            type,
            data,
            critical: critical,
            isLong: reader.isLong,
          ));
        }
      }

      expect(initSubpackets.length, subpackets.length);
      for (final subpacket in initSubpackets) {
        final index = initSubpackets.indexOf(subpacket);
        expect(subpacket.type, subpackets[index].type);
        expect(subpacket.data, equals(subpackets[index].data));
      }
    });

    test('KeyFlag', () {
      final keyFlags = KeyFlags.fromFlags(
        KeyFlag.certifyKeys.value |
            KeyFlag.signData.value |
            KeyFlag.encryptCommunication.value |
            KeyFlag.encryptStorage.value |
            KeyFlag.splitPrivateKey.value |
            KeyFlag.authentication.value |
            KeyFlag.sharedPrivateKey.value,
      );
      for (final flag in KeyFlag.values) {
        expect(keyFlags.flags & flag.value, flag.value);
      }
      expect(keyFlags.isCertifyKeys, isTrue);
      expect(keyFlags.isSignData, isTrue);
      expect(keyFlags.isEncryptCommunication, isTrue);
      expect(keyFlags.isEncryptStorage, isTrue);
    });

    test('Features', () {
      final features = Features.fromFeatures(
        SupportFeature.seipdV1.value |
            SupportFeature.aead.value |
            SupportFeature.publicKeyV5.value |
            SupportFeature.seipdV2.value,
      );
      expect(features.seidpV2Supported, isTrue);
      expect(features.aeadSupported, isTrue);
      expect(features.publicKeyV5Supported, isTrue);
      expect(features.seidpV2Supported, isTrue);
    });

    test('Salt notation', () {
      final saltNotation = NotationData.saltNotation(16);
      expect(saltNotation.notationName, NotationData.saltName);
      expect(saltNotation.valueData.length, 16);
    });
  });

  group('One-Pass Signature', () {
    test('Version 3', () {
      const signatureData = '''
BAEBCgBtBYJnOHr4CZD7/MgqAV5zMEUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMu
b3JnOjEa9EOdbhBhQV8InW6o4SNTRRHi1SlZZb7xXxYI7U4WIQTRpm4aI7GCyZgPeIz7/MgqAV5z
MAAAy7IL/17BbwLPAXrf6xhjeYU7JJrLODcW9sbEz0NmmnppO2AsYAGYFtBz/K4USDLGV9EeyVX+
hsbcsOXV+nS07ZbY3PhJU2/xyVba/iEVzde0GkOSfI87VZ7WW26jytsnSYjN8uvXJG3pHTjHPiD9
krfOCoUlN/CEp85tkS4nZ68x6eI/6PYtR/S4e4DWGtF5uB3Y3xLAbgPX03v0/sonjs21By9i7uy0
JZI0/nsU0mJDU04p8jOKhYBy3W4O2GboZ8T3YEnpeDxpkbi6ZEVrMi/j3MfgDrl46IQxK8Xaru+E
LugRLCSgY5lrz+6G8v0d2oU/YpwLs7XpRgDszOCSp1aJZoP4wqMqqE8COzq2dJc52b0ysYsxmxtr
nk3eLE5XsXU7oSq1HMFQkxMS7NiEbG8FPpwGdd+4NOOZj6Wli/DzMfBwf1sGj6wcvGLlLMGGHScc
j1AUElFDMJNJEXHK6cgf51OphuFdfgqUmymRmCPh2FehrykW6sUL2YcV1igpUB1wRQ==
''';
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      final ops = OnePassSignaturePacket.fromSignature(signature);
      expect(ops.version, 3);
      expect(ops.signatureType, signature.signatureType);
      expect(ops.hashAlgorithm, signature.hashAlgorithm);
      expect(ops.keyAlgorithm, signature.keyAlgorithm);
      expect(ops.issuerKeyID, signature.issuerKeyID);
    });

    test('Version 6', () {
      const signatureData = '''
BgEbCgAAACkFgmc4euIioQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9lJewnutmsyQAAAADkJyCU
jQRajkQCbyj5lwWuYQL8v+POcIyOEQPiE0ieuHH2CyqwLxNq8KQ06K8+4PLazLhcdk8A34nfuiGS
CcHUtYDD2WgFQiCPnL6DfYYdS2ttmRWtQkCGmw6oumQ0LHU7ig4=
''';
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      final ops = OnePassSignaturePacket.fromSignature(signature);
      expect(ops.version, 6);
      expect(ops.signatureType, signature.signatureType);
      expect(ops.hashAlgorithm, signature.hashAlgorithm);
      expect(ops.salt, signature.salt);
      expect(ops.issuerFingerprint, signature.issuerFingerprint);
      expect(ops.issuerKeyID, signature.issuerKeyID);
    });
  });

  group('Verification', () {
    const literalText = 'Hello World :)';

    test('Verify with RSA key', () {
      const keyData = '''
BF2lnPIBDAC5cL9PQoQLTMuhjbYvb4Ncuuo0bfmgPRFywX53jPhoFf4Zg6mv/seOXpgecTdOcVtt
fzC8ycIKrt3aQTiwOG/ctaR4Bk/t6ayNFfdUNxHWk4WCKzdz/56fW2O0F23qIRd8UUJp5IIlN4RD
dRCtdhVQIAuzvp2oVy/LaS2kxQoKvph/5pQ/5whqsyroEWDJoSV0yOb25B/iwk/pLUFoyhDG9bj0
kIzDxrEqW+7Ba8nocQlecMF3X5KMN5kp2zraLv9dlBBpWW43XktjcCZgMy20SouraVma8Je/ECwU
WYUiAZxLIlMv9CurEOtxUw6N3RdOtLmYZS9uEnn5y1UkF88o8Nku890uk6BrewFzJyLAx5wRZ4F0
qV/yq36UWQ0JB/AUGhHVPdFf6pl6eaxBwT5GXvbBUibtf8YI2og5RsgTWtXfU7ebSGXrl5ZMpbA6
mbfhd0R8aPxWfmDWiIOhBufhMCvUHh1sApMKVZnvIff9/0Dca3wbvLIwa3T4CyshfT0AEQEAAQ==
''';
      const signatureData = '''
BAEBCgBtBYJnOHr4CZD7/MgqAV5zMEUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMu
b3JnOjEa9EOdbhBhQV8InW6o4SNTRRHi1SlZZb7xXxYI7U4WIQTRpm4aI7GCyZgPeIz7/MgqAV5z
MAAAy7IL/17BbwLPAXrf6xhjeYU7JJrLODcW9sbEz0NmmnppO2AsYAGYFtBz/K4USDLGV9EeyVX+
hsbcsOXV+nS07ZbY3PhJU2/xyVba/iEVzde0GkOSfI87VZ7WW26jytsnSYjN8uvXJG3pHTjHPiD9
krfOCoUlN/CEp85tkS4nZ68x6eI/6PYtR/S4e4DWGtF5uB3Y3xLAbgPX03v0/sonjs21By9i7uy0
JZI0/nsU0mJDU04p8jOKhYBy3W4O2GboZ8T3YEnpeDxpkbi6ZEVrMi/j3MfgDrl46IQxK8Xaru+E
LugRLCSgY5lrz+6G8v0d2oU/YpwLs7XpRgDszOCSp1aJZoP4wqMqqE8COzq2dJc52b0ysYsxmxtr
nk3eLE5XsXU7oSq1HMFQkxMS7NiEbG8FPpwGdd+4NOOZj6Wli/DzMfBwf1sGj6wcvGLlLMGGHScc
j1AUElFDMJNJEXHK6cgf51OphuFdfgqUmymRmCPh2FehrykW6sUL2YcV1igpUB1wRQ==
''';

      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Verify with DSA key', () {
      const keyData = '''
BF3+CmgRDADZhdKTM3ms3XpXnQke83FgaIBtP1g1qhqpCfg50WiPS0kjiMC0OJz2vh59nusbBLzg
I//Y1VMhKfIWYbqMcIY+lWbseHjl52rqW6AaJ0TH4NgVt7vhyVeJt0k/NnxvNhMd0587KXmfpDxr
wBqc/l5cVB+p0rL8vs8kxojHXAi5V3koM0UjREWs5Jpj/XU9LhEoyXZkeJC/pes1u6UKoFYn7dFI
P49Kkd1kb+1bNfdPYtA0JpcGzYgeMNOvdWJwn43dNhxoeuXfmAEhA8LdzT0C0O+7akXOKWrfhXJ8
MTBqvPgWZYx7MNuQx/ejIMZHl+Iaf7hG976ILH+NCGiKkhidd9GIuA/WteHiQbXLyfiQ4n8P12q9
+4dq6ybUM65tnozRyyN+1m3rU2a/+Ly3JCh4TeO27w+cxMWkaeHyTQaJVMbMbDpXduVd32MA33UV
NH5/KXMVczVi5asVjuKDSojJDV1QwX8izZNl1t+AI0L3balCabV0SFhlfnBEUj1my1sBAMOSO/I6
7BvBS3IPHZWXHjgclhs26mPzRlZLryAUWR2DDACH5fx+yUAdZ8Vu/2zWTHxwWJ/X6gGTLqa9CmfD
q5UDqYFFzuWwN4HJ+ryOuak1CGwSKJUBSA75HExbv0naWg+suy+pEDvF0VALPU9VUkSQtHyR10YO
2FWOe3AEtpbYDRwpdr1ZwEbb3L6IGQ5i/4CNHbJ2u3yUeXsDNAvrpVSEcIjA01RPCOKmf58SDZp4
yDdPxGhM8w6a18+fdQr22f2cJ0xgfPlbzFbO+FUsEgKvn6QTLhbaYw4zs7rdQDejWHV82hP4K+rb
9FwknYdV9uo4m77MgGlU+4yvJnGEYaL3jwjI3bH9aooNOl6XbvVAzNzomYmaTO7mp6xFAu43yuGy
d9K+1E4k7CQTROxTZ+RdtQjV95hSsEmMg792nQvDSBW4xwfOQ7pf3kC7r9fm8u9nBlEN12HsbQ8Y
vux/ld5q5RaIlD19jzfVR6+hJzbj2ZnUyQs4ksAfIHTzTdLttRxS9lTRTkVx2vbUnoSBy6TYF1mf
6nRPpSm1riZxnkR4+BQL/0rUAxwegTNIG/5M612s2a45QvYK1turZ7spI1RGitJUIjBXUuR76jIs
yqagIhBl5nEsQ4HLv8OQ3EgJ5T9gldLFpHNczLxBQnnNwfPoD2e0kC/iy0rfiNX8HWpTgQpbzAos
Lj5/E0iNlildynIhuqBosyRWFqGva0O6qioL90srlzlfKCloe9R9w3HizjCbf59yEspuJt9iHVNO
POW2Wj5ub0KTiJPp9vBmrFaB79/IlgojpQoYvQ77Hx5A9CJqpaMCHGOW6Uz9euN1ozzETEkIPtL8
XAxcogfpe2JKE1uS7ugxsKEGEDfxOQFKAGV0XFtIx50vFCr2vQro0WB858CGN47dCxChhNUxNtGc
11JNEkNv/X7hKtRf/5VCmnazGWwNK47cqZ7GJfEBnElD7s/tQvTC5Qp7lg9gEt47TUX0bjzUTCxN
vLosuKL9+J1Wln1myRpff/5ZOAnZTPHR+AbX4bRB4sK5zijQe4139Dn2oRYK+EIYoBAxFxSOzehP
IQ==
''';
      const signatureData = '''
BAARCgBvBYJnOHrmCRCbp4ncdtaEmkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBn
cC5vcmfMz7rhDJDNvMygIAtM2lpYtNV/Uo1hX/2TeWCVF09y4xYhBHH/2gBECeXdsMPo8Zunidx2
1oSaAABjEAEAkWtxWQf/FdyetrTz9auRmtoGmXOSSmyD8FCeaZTTS6YBAKO4IcYMynJnEzMRpTvK
EzSE9lH3RInTOtPd+ICKWrA7
''';

      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Verify with ECDSA NIST P-384 key', () {
      const keyData = '''
BGc/+YkTBSuBBAAiAwMEd3FJXIrlQksBiwOLB+ksANWsTQzFNxqpxzjpglaDNKjgF/RXVXj9A6os
ao0WJtqkKFKZvkASvOCgOaBn3GDUZmF8GJwuuLNOci0JC/N+g5nFd/BeXNJNyECMIbllcLt9
''';
      const signatureData = '''
BAATCQBdBQJnSYcNFiEEoyUQfma8qz7qQHVQOW7Li7htGSIJEDluy4u4bRkiNRQAAAAAABQAGHNh
bHRAcGhwLW9wZW5wZ3Aub3Jn67K0PLenjKjdnfzO74JVwHinZH47yg9GAAA0CgF8Dth3ap+Dc8+3
4OamLRo8MRCH2fBbjRNPxtKjz1ZG9NDOF6KePoSv57ijpwPjXpIuAX0RhdUWB1HX6lY/f2zcVetC
CqiCSnlWWoGYsnbr2P8E9ra3g7s5O9vEM0v78eEYaNs=
''';

      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Verify with ECDSA Brainpool P-256 key', () {
      const keyData = '''
BGc/+dATCSskAwMCCAEBBwIDBJ15ari0PCq317awmdNNIwz+yOZ18yUCg8LOAmYEaRAqAh1HmAnS
K5d4i1CX2M2/UKup7f/KD/o5Y6oid+VuTZQ=
''';
      const signatureData = '''
BAATCABVBQJnSYZUFiEEzRtbFClPgL5lzvvvmVEhn8nelXgJEJlRIZ/J3pV4LRQAAAAAABQAEHNh
bHRAcGhwLW9wZW5wZ3Aub3JnxGTgM/wcO2Hyp0OjyEEnVwAAXiwA/3ZoYHQHEJnc279Wu4YgTGNH
HEfWo+l0t+wTCKJUh9iuAQCcmwa2Jh5BJNJd9ezMwPyH/uCgYyyemg9S1J5xNKFepw==
''';

      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Verify with EdDSA legacy key', () {
      const keyData = '''
BFxHBOkWCSsGAQQB2kcPAQEHQK41sJNxQKsohWxQSk+E813FQaj0wd4Js5Qv1G+ztbtd
''';
      const signatureData = '''
BAEWCgBtBYJnOHrpCZDyMVUMT0fjjkUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMu
b3JnzMEymyavaUnENgbL9jraEbtusliXCI43HBlvu7fvL54WIQTrhbtfozp14V6UTmPyMVUMT0fj
jgAApJYBAJfdeqUkAmab94505yS83p2JkPMqJEMbrH9G0LdjPkRaAP4//ZOdoZm7IoOyjelKc0LC
emD753kKao1uctpHT1WHDw==
''';

      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Verify with Ed25519 rfc9580 key', () {
      const keyData = '''
BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWj
''';
      const signatureData = '''
BgEbCgAAACkFgmc4euIioQbLGGxPBgmml+TVLfpscisMHx4nwYpWcI9lJewnutmsyQAAAADkJyCU
jQRajkQCbyj5lwWuYQL8v+POcIyOEQPiE0ieuHH2CyqwLxNq8KQ06K8+4PLazLhcdk8A34nfuiGS
CcHUtYDD2WgFQiCPnL6DfYYdS2ttmRWtQkCGmw6oumQ0LHU7ig4=
''';

      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Verify with Ed448 rfc9580 key', () {
      const keyData = '''
BmbzftccAAAAOR3+OzyG7CwqCJopfjLl1hr1L8xJb4yIqt3ya0SH/pNXF63tthhChdNUdqtTGppE
g6KH7Dz3jXlFAA==
''';
      const signatureData = '''
BgAcCAAAADMFAmdJlAEiIQajZpX32QU9YiluDfY6DUi6J3MNnD1PcbgqWMinyQ/qIAkQo2aV99kF
PWIAAAAAUIoQbFoa0AGrM/71CxsKoDRGUBDJuaNAY5eefCAWYJyMKaQHktcakEk22D9FFV/jonlA
1Wc7R087rKOb7OF7ikAFCvJZNm04770BgPph3pY2wRU82uD/J5P+DBi7pKj63EXAPzla/jmY3cs9
sU42Y3hMyl3ZAZyV2uFHbqAUz+KbMO4oAA==
''';

      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          keyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.fromBytes(
        base64.decode(
          signatureData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );

      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });
  });

  group('Signing', () {
    const literalText = 'Hello World :)';

    test('Sign with RSA key', () {
      const secretKeyData = '''
BGc/4FEBCACZXe5kmfKWChtAGdoYRxRkEcfm0Ne431ovB4QS3zIOoclfyA7jgyq1UAhKbsYhZmTK
xx0FO5/HKOO2ojJU3AeKbLP+xhH8yVdEK5JiySvX/16Tz27d+r5WGLkjZMYZAxWW9hdfurajYp8v
cdACvErKMXShXUR9npCKH5O0QBagxMg6vczfJfNG1qWJ9aeFO7yffUt9n+39ru3Cc67EAp7m29Wo
wto15xmeXCPkYEgE+BM+86AHGqihOERjPCzWeFVLRuCwj2YjmZvtMh9A2gx5K6dMQ5viMDsTSoB0
DEZzvY+Q7gr7/qiWCpSfmy3gvmReOvMzk8uI7+Nt6vdJia4vABEBAAEAB/oDLokNzxuJgcRP9n3p
MJoJMkz0LwElARb1GYjjtVdHKSX2TKwEHi7hSalqXwwah7c44y4yKhi4SWU9KD9JNiA+x977PsqV
dMcHfRntAyokw/h0+5Q3Ub16J+8CNlPvyjDOQpvBrQd6jZAqmeNehXHyV8ebTI8gRg08nOwYenJ5
KTYIZTFaZ2kvVkV1ihbaUk5AGQsFsh8e3Y+Zh2KfjJfl2ykng23SMocF99Lth7ityO8LYFSk1iNk
IeLqAxC3yblEtr2QYSlOwmXjU5Mos7PGHuBZjvEpwDqyZTuAMFhN0e/iPKtejFp6u5OOtABwUE7s
rB9tQ7DnB5nXfaprzemFBADDRLSHU4ICg8lGwBFF+XtlQ+pmv3AawiwjV0DUcCxDu3YUBbnyZPIe
J5CAIzLE7syNFgL2y4LB2396ej5weEE+1bmbKDQZ3YDKqI02qy540dqPdEtikW8tLUZbWkwooTLk
+Ltv8USNc1dyHYdHFgv6m0fUOmgEjJJpkQEUsv8m9QQAyREGq2qL9TGY2NHAKBGQprzm8KduW1Z+
3sN0BkcFJDMsYaH05dekh5o/p/b1cc22hhaNUtiK9goqNUPXqLTZwU/8w7piblPzcSx7xWP5yWbh
s43PqR7I56PHuZ5HNk8IfxFnFxSfr+eUzoHkSuZeXcuuvdOBXJOqLCa7t9bwYhMD/0G/N+W0KEve
Wk723L6iG1cWrX7uKQLo9L4zdvn1CknANvGWD8UBjDk4QJKl4EFE1FWp/uFjQ9mcP7u/F3S+Ekhv
nXllXNZ1lBvdnmW0xkPwd3MJFpQ269Q46Fgw2t5mQ2B44qvAEXfs7XvpHQOkpBJnpPVDKvXbciXf
Sl6rNjITOic=
''';
      const publicKeyData = '''
BGc/4FEBCACZXe5kmfKWChtAGdoYRxRkEcfm0Ne431ovB4QS3zIOoclfyA7jgyq1UAhKbsYhZmTK
xx0FO5/HKOO2ojJU3AeKbLP+xhH8yVdEK5JiySvX/16Tz27d+r5WGLkjZMYZAxWW9hdfurajYp8v
cdACvErKMXShXUR9npCKH5O0QBagxMg6vczfJfNG1qWJ9aeFO7yffUt9n+39ru3Cc67EAp7m29Wo
wto15xmeXCPkYEgE+BM+86AHGqihOERjPCzWeFVLRuCwj2YjmZvtMh9A2gx5K6dMQ5viMDsTSoB0
DEZzvY+Q7gr7/qiWCpSfmy3gvmReOvMzk8uI7+Nt6vdJia4vABEBAAE=
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          secretKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          publicKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.createSignature(
        secretKey,
        SignatureType.standalone,
        literalText.toBytes(),
      );
      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Sign with ECDSA NIST P-384 key', () {
      const secretKeyData = '''
BGc/+YkTBSuBBAAiAwMEd3FJXIrlQksBiwOLB+ksANWsTQzFNxqpxzjpglaDNKjgF/RXVXj9A6os
ao0WJtqkKFKZvkASvOCgOaBn3GDUZmF8GJwuuLNOci0JC/N+g5nFd/BeXNJNyECMIbllcLt9AAGA
45H1wvi7/byiPz3owPhTAh0Pxc/T/U+MiGt/qGO3dVKRfIwlBVMbMb0JDMkBSARKGCU=
''';
      const publicKeyData = '''
BGc/+YkTBSuBBAAiAwMEd3FJXIrlQksBiwOLB+ksANWsTQzFNxqpxzjpglaDNKjgF/RXVXj9A6os
ao0WJtqkKFKZvkASvOCgOaBn3GDUZmF8GJwuuLNOci0JC/N+g5nFd/BeXNJNyECMIbllcLt9
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          secretKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          publicKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.createSignature(
        secretKey,
        SignatureType.standalone,
        literalText.toBytes(),
      );
      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Sign with ECDSA Brainpool P-256 key', () {
      const secretKeyData = '''
BGc/+dATCSskAwMCCAEBBwIDBJ15ari0PCq317awmdNNIwz+yOZ18yUCg8LOAmYEaRAqAh1HmAnS
K5d4i1CX2M2/UKup7f/KD/o5Y6oid+VuTZQAAQCAetZiozf4F0b5trgEPGOsbT4PYke6PlfnRjlP
s4Zxog7L
''';
      const publicKeyData = '''
BGc/+dATCSskAwMCCAEBBwIDBJ15ari0PCq317awmdNNIwz+yOZ18yUCg8LOAmYEaRAqAh1HmAnS
K5d4i1CX2M2/UKup7f/KD/o5Y6oid+VuTZQ=
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          secretKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          publicKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.createSignature(
        secretKey,
        SignatureType.standalone,
        literalText.toBytes(),
      );
      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Sign with EdDSA legacy key', () {
      const secretKeyData = '''
BGc/+gYWCSsGAQQB2kcPAQEHQGUAHTxwcB6TD72goFQpLf3jAqdbm1cZwv1N2mjBffEgAAD/fBmt
MQFsViG6cDhKa8Mjx3gK1PRMy9CXs375s8jmjlERTA==
''';
      const publicKeyData = '''
BGc/+gYWCSsGAQQB2kcPAQEHQGUAHTxwcB6TD72goFQpLf3jAqdbm1cZwv1N2mjBffEg
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          secretKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          publicKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.createSignature(
        secretKey,
        SignatureType.standalone,
        literalText.toBytes(),
      );
      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Sign with Ed25519 rfc9580 key', () {
      const secretKeyData = '''
BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWjABlygXsSvnB+jV9YbOYT
YSAdNE6yZqLIL95oNXYrZbC3
''';
      const publicKeyData = '''
BmOHf+MbAAAAIPlNp7tI1gph5WdwamWH0DMZmbudiRoIJC6thFQ9+JWj
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          secretKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          publicKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.createSignature(
        secretKey,
        SignatureType.standalone,
        literalText.toBytes(),
      );
      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });

    test('Sign with Ed448 rfc9580 key', () {
      const secretKeyData = '''
BmbzftccAAAAOR3+OzyG7CwqCJopfjLl1hr1L8xJb4yIqt3ya0SH/pNXF63tthhChdNUdqtTGppE
g6KH7Dz3jXlFAAD8C816Koa0GGjpC5lWzhe5Ve8u3Q567f44XWum3y63z8fldhY1jvB2ixSGZtNc
yFlK9T9y2q2KGTA=
''';
      const publicKeyData = '''
BmbzftccAAAAOR3+OzyG7CwqCJopfjLl1hr1L8xJb4yIqt3ya0SH/pNXF63tthhChdNUdqtTGppE
g6KH7Dz3jXlFAA==
''';
      final secretKey = SecretKeyPacket.fromBytes(
        base64.decode(
          secretKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final publicKey = PublicKeyPacket.fromBytes(
        base64.decode(
          publicKeyData.replaceAll(
            RegExp(r'\r?\n', multiLine: true),
            '',
          ),
        ),
      );
      final signature = SignaturePacket.createSignature(
        secretKey,
        SignatureType.standalone,
        literalText.toBytes(),
      );
      expect(signature.verify(publicKey, literalText.toBytes()), isTrue);
    });
  });
}
