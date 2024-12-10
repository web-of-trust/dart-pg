import 'package:dart_pg/src/openpgp.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  group('Verify detached', () {
    const literalText = 'Hello World :)';

    test('with key Bob', () {
      const signature = '''
-----BEGIN PGP SIGNATURE-----

wsEpBAABCABdBYJnSvMCCZD7/MgqAV5zMDUUAAAAAAAcABBzYWx0QG5vdGF0aW9u
cy5vcGVucGdwanMub3Jncfoti0U5ghCOKmx5M7vbKBYhBNGmbhojsYLJmA94jPv8
yCoBXnMwAABkYgv/dmXdeyHyGswzYiqG0u9Tf/zIAupHT3XByvFO4G4XqbOczc7r
bhWcku/bMjbqEr+16PqUrjknn/ZEhrCGZDJROxdVT+3FUnLkiTXOw+0Cb2tR29Rl
2qOWa7iKj1vE2qBEqQt1BCqM9OOFRCpawQp1aE/zDgjdR3pbNLGinK+tq2oj0GwT
8PA4CSnOnCVR+JNS+i8K8yKLo2m/GpBiHnMQ+ZlzPtY9lqNpQrIJXrN8q14oRZzO
KE6+DJJPmngh34LbqpZRxSfrFhZo/qdJGPwH2hi43dn/1PrS4w6Kpv/tGcHzhd7o
of+B9CPbeYhsB0MIVV2JX5FwTXwolEtHXRMpKv13MiRZaSeW49VkutzCJTweWLOS
6f2bx9xLnwwQU9u2n0obPTtQFd/CG2pc1uteX2DUyfmhcyTKEk9bJbdelK2YXteh
lvVdIiEZ2ukMebLI1UZqRofBRTIawPlDSHYe40x6PaeiZTMyMUHpcJeCrmwIs1Tx
zulYLxB5IjCH4MHD
=7AKp
-----END PGP SIGNATURE-----
''';
      final verifications = OpenPGP.verifyDetached(
        literalText,
        signature,
        [OpenPGP.readPublicKey(bobPublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'fbfcc82a015e7330');
      }
    });

    test('with key Carol', () {
      const signature = '''
-----BEGIN PGP SIGNATURE-----

wr0EABEKAG8FgmdK8yIJEJunidx21oSaRxQAAAAAAB4AIHNhbHRAbm90YXRpb25z
LnNlcXVvaWEtcGdwLm9yZxoGn2+mAvpD6F4t/5Mv8G+bAYvqtBMfZnt7DgK9w5hj
FiEEcf/aAEQJ5d2ww+jxm6eJ3HbWhJoAAMgfAP9K3yH+1UbwF1rHkIZWPmXcNp9H
VfWNEL0YDVD/chX5FwD/WlWByOZFFlhObRyo/0NVyUa3ZJX2ZJD2ro2kDOWQryg=
=7T8U
-----END PGP SIGNATURE-----
''';
      final verifications = OpenPGP.verifyDetached(
        literalText,
        signature,
        [OpenPGP.readPublicKey(carolPublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), '9ba789dc76d6849a');
      }
    });

    test('with key Alice', () {
      const signature = '''
-----BEGIN PGP SIGNATURE-----

wrsEABYKAG0FgmdK8nwJkPIxVQxPR+OORRQAAAAAABwAIHNhbHRAbm90YXRp
b25zLm9wZW5wZ3Bqcy5vcmcQY0f4qE+jcGriU6TzdxVcZSYLXnJc7+8wxER4
dhvc/RYhBOuFu1+jOnXhXpROY/IxVQxPR+OOAABSKgD/Ru+U4YtagCKdx6wy
AixSwExUcmhM0KL3yJcE8oUd5agBALC4yA7lz2Ri489Zs0whRcfXZjTIM8Ga
P7gvxbUc0GsL
=BBPw
-----END PGP SIGNATURE-----
''';
      final verifications = OpenPGP.verifyDetached(
        literalText,
        signature,
        [OpenPGP.readPublicKey(alicePublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'f231550c4f47e38e');
      }
    });

    test('with key from RFC9580', () {
      const signature = '''
-----BEGIN PGP SIGNATURE-----

wpgGABsKAAAAKQWCZ0ryciKhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul
7Ce62azJAAAAAHlcIJnq4Ut3hpyC3QLKpEiPNbKIu9jLN6v+v9OQtsay2sJ1
i6UgQbwhFpsEXmXEZePugZCqC26UmoFor/Ju80rseo9mXnSkmPJj1BuE+5wG
3WpEmDMxR0D/51a8cC+2BBn4Cw==
-----END PGP SIGNATURE-----
''';
      final verifications = OpenPGP.verifyDetached(
        literalText,
        signature,
        [OpenPGP.readPublicKey(rfc9580PublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'cb186c4f0609a697');
      }
    });
  });

  group('Verify inline', () {
    test('with key Bob', () {
      const message = '''
-----BEGIN PGP MESSAGE-----

xA0DAAoB+/zIKgFeczAByxRiAGdK8nNIZWxsbyBXb3JsZCA6KcLBOQQAAQoA
bQWCZ0rycwmQ+/zIKgFeczBFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3Bl
bnBncGpzLm9yZ6vzZTkkQwaMoqVBpRFpUhVfjvBXVDZ7JoJaoRQMTB0/FiEE
0aZuGiOxgsmYD3iM+/zIKgFeczAAADFdC/9M8de86hvnyOB5Q5SIpUs3NIis
XDHCgeEgAAuXyIqNuWsZYfcbd6GXIWfhJunSCzXMmC+K3YkSkIpm9L3bPzxf
xlxC9oHCRKgIb5CZp8nlKis17Pg8S9jBPP7rk5/Q+pYCoGEbLpsg5ryJ7Clg
x3uVxnChqRiWTy/MG0k8LWBss/BQo6WVk8j3ME4+Yz7M1hTlCRgCbA52ICtk
yajvo5ZYIa4WSX9bgy79Tv5VtBhplfmCepBmdJcGF1POu2ZOkp+FIEySwcH+
ykmM9a/7gQdOiFrS/PAZlGV3uOv2V6eoaBxwnsU2vOfkWX8s6RltEZOwJ5TJ
Etshm3Rxcnv2fXLO/xMs8zu896qYZMueZ4jXGk+Iut5QtVtZZJxxW8Q+/oWR
FYXusxNdYrb12viqsjpdJ4m/oH2q6556e3zmvO7rlL/RnlWCdtOnFhfL8hyF
XtCxLFlvTgqqMZFQGT0mZcVmcP2prcBvppxqyjKaEccO1GS4mJ/BTJkFWfA3
AgYWB/E=
=Fi+1
-----END PGP MESSAGE-----
''';
      final verifications = OpenPGP.verifyInline(
        message,
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

xA0DAAoRm6eJ3HbWhJoByxRiAAAAAABIZWxsbyBXb3JsZCA6KcK9BAARCgBvBYJn
SvLnCRCbp4ncdtaEmkcUAAAAAAAeACBzYWx0QG5vdGF0aW9ucy5zZXF1b2lhLXBn
cC5vcme39jeR4Dm6DkXxp9TVRLYmydOKTSeGdGLcXgv78QnCLBYhBHH/2gBECeXd
sMPo8Zunidx21oSaAAAmhgEAvVOllWNmbX/9v/3MDbwSolVZoOhHHj8KEbVv0iRT
WnEBAMAO5xOUJ/DjT/dPn+D95gk7PleCYBBPX7kdfOWVXJjt
=0h5J
-----END PGP MESSAGE-----
''';
      final verifications = OpenPGP.verifyInline(
        message,
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

xA0DAAoW8jFVDE9H444ByxRiAGdK8rVIZWxsbyBXb3JsZCA6KcK7BAAWCgBt
BYJnSvK1CZDyMVUMT0fjjkUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVu
cGdwanMub3JnfPNT4vSssXxZkCUaXVOjNZ2Xfmk+zuEbBLV6VH3jPDgWIQTr
hbtfozp14V6UTmPyMVUMT0fjjgAAAVIBAJmGEARKx44At+Q+3yB03g1K6YXC
SjsuuqTYd5OV3P08AP4gjbsJVlPLXf8Kk0E0daoVBCx9Ypa8DhVAAl1HsIbQ
Bg==
=aG5M
-----END PGP MESSAGE-----
''';
      final verifications = OpenPGP.verifyInline(
        message,
        [OpenPGP.readPublicKey(alicePublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'f231550c4f47e38e');
      }
    });

    test('with key from RFC9580', () {
      const message = '''
-----BEGIN PGP MESSAGE-----

xEYGAAobIPGbvDQPJYi9/qkn2Wcrl0z39nMJVJTDUxFmyNPmvC9PyxhsTwYJ
ppfk1S36bHIrDB8eJ8GKVnCPZSXsJ7rZrMkByxRiAGdK8mlIZWxsbyBXb3Js
ZCA6KcKYBgAbCgAAACkFgmdK8mkioQbLGGxPBgmml+TVLfpscisMHx4nwYpW
cI9lJewnutmsyQAAAACuKCDxm7w0DyWIvf6pJ9lnK5dM9/ZzCVSUw1MRZsjT
5rwvT5z78KFKbCRryWKPwitzIEWXNzbS1DmZNigFFzBJ81sW2iV12iaHtQbD
Keo3KDD1pX3QV6YKK+dWuA34xgJ5bAw=
-----END PGP MESSAGE-----
''';
      final verifications = OpenPGP.verifyInline(
        message,
        [OpenPGP.readPublicKey(rfc9580PublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'cb186c4f0609a697');
      }
    });
  });
}
