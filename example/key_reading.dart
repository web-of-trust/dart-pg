import 'package:dart_pg/dart_pg.dart';
import 'package:dart_pg/src/common/helpers.dart';

void main() {
  const rsaKeyData = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=6yWV
-----END PGP PUBLIC KEY BLOCK-----
''';

  const eccKeyData = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

xpMEZvNvEhMFK4EEACMEIwQAhYLZkwYSvw0U+DPzSGOQybF7GZ3OoZpk6kXgyn2CJEk8jLAdvnNG
2lZPHgCbm7PCMorp+lDpwQgRlGOPAWTkoa8Ao6CC/WPqEgu8c9YbWKrMaB1MTqlzsKrpbuOQC1mS
dG4M4/wuc53Y7jK479RsAX+HrO3aShyJ6fWa2fERWVJlk+vNKk5ndXllbiBWYW4gTmd1eWVuIDxu
Z3V5ZW5udjE5ODFAZ21haWwuY29tPsLAOAQQEwoAZwUCZvNvEhYhBIZiN9Hgecmhdbnw0UCmua4K
K7P9CRBAprmuCiuz/QIZATwUAAAAAAATACBzYWx0QHdlYm9mdHJ1c3Qub3JnTHkM5KPVLr04ZPWh
qKfnT9FRgGijUcEruixX0t7jzK4AAKyqAgYi176jK907bBygy73ZwNdProB8NXPbSLXndH5uk+bG
cvYoVuHJztKt7lq6bstUrrLaPC7aAtBKKGEAtoXle0hHpgIJAeXy7hhs05lPC1Da62TTIqY81vfK
GbiXDQ6nRFUwsmX0/gKJv8vlhaU80j8MWC6JEXSb8we2m/hIDUoZua17HlgWzSxOZ3V5ZW4gVmFu
IE5ndXllbiA8bmd1eWVubnZAaXdheXZpZXRuYW0uY29tPsLANQQQEwoAZAUCZvNvEhYhBIZiN9Hg
ecmhdbnw0UCmua4KK7P9CRBAprmuCiuz/TwUAAAAAAATACBzYWx0QHdlYm9mdHJ1c3Qub3JnITBv
QWh34a2PFstAFRfyvySvaLZr4IRPLgEK5IQjq7oAACCKAgj/TsIuuLLm7npWEBy2vDSyIbEdejMq
6kc9jE7ZdJDHn5+2QYM1ABeKrZ5RQIFKGNV6UDEcuC2y5efTfaiXUYXIRwIJAWcKN26eFbNvE0Ox
kPTfvB12Co/9xlPqe6jZu2Tu5zCZihWwNyeMBrbKb2w8z5K6ojRNUzmeKqeWWs3tjXShLcLnzpcE
ZvNvEhIFK4EEACMEIwQA2d2DuFoHSMxLak3N9vIGd6ULDtAU2ND2P+udyCmw7bELsdaHkTLzuP8e
VvXGu9kubwplQ2QPO84Qu2QSw8JGWGwAGsOsZmE/mKQ+kAdrWPegS6EzlbjHY1zDGwU9QRPb0dKI
rnxHLM2Ao8PXIDMWzGtNVSCk/3jae2EPYAO3a0PCqNgDAAoJwsA3BBgTCgBnBQJm828SFiEEhmI3
0eB5yaF1ufDRQKa5rgors/0JEECmua4KK7P9AhsMPBQAAAAAABMAIHNhbHRAd2Vib2Z0cnVzdC5v
cmcFEoHRwxZoRuqWJKVrwMC99WEqEYlFml390bKcml981QAAtHcCCJEkfTugD4paRzEcnqSTOPRG
J5yYt/JqDKCwUVC90rWc+kBrR5YXGjOev5sUPVwUeATTf5Q4/diHEF5fBe6GQxyVAgdn/JTcu0nF
oRO4ZVyMBu0Exd8BB/S/CNoqXyel6UiKBiNQN/SA7jwuUQqrW+10+84ZHL41TxpiegwAt08fw0Lt
Xg==
=QRfd
-----END PGP PUBLIC KEY BLOCK-----
''';

  const curve25519KeyData = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGZvNvEhsAAAAgHVrZBj0nDKrbf0Tu8fWOjRiPaMulfxm1Mt7lEkY4gZzCuwYfGwgAAABcBQJm
828SIiEGoLT+uXrwY1ghIpvsuo3SXJzh9HEg0y3OT6Vr6OoCSYMJEKC0/rl68GNYAhsDAwsHCQQi
AQIDBRUIDAoOBRYAAQIDAh4LDScHAQkBBwIJAgcDCQMAAAAAud0QHptvcH5rYd3HpH27Oymyc4u5
2xIfEx0ktluI0xBx5BunedkVFkZCDn4kF8l+LoY2JRHOHELTGOE0tr27dWeNxyWD12JNQFfNmwEn
hjXPRg7NKk5ndXllbiBWYW4gTmd1eWVuIDxuZ3V5ZW5udjE5ODFAZ21haWwuY29tPsK+BhAbCAAA
AF8FAmbzbxIiIQagtP65evBjWCEim+y6jdJcnOH0cSDTLc5PpWvo6gJJgwkQoLT+uXrwY1gCGwMD
CwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcBCQEHAgkCBwMJAwIZAQAAAAAYkhCK+OAsSwTaVp3J
z3lg1pTZ3b1CLmHiovJCIOCNmSD2Xd039LaL1WzjwGtFqkGLZGrljKtctyZA9J0zCPll5wSNtZdp
bZogWYv7tpG9u56zAc0sTmd1eWVuIFZhbiBOZ3V5ZW4gPG5ndXllbm52QGl3YXl2aWV0bmFtLmNv
bT7CuwYQGwgAAABcBQJm828SIiEGoLT+uXrwY1ghIpvsuo3SXJzh9HEg0y3OT6Vr6OoCSYMJEKC0
/rl68GNYAhsDAwsHCQQiAQIDBRUIDAoOBRYAAQIDAh4LDScHAQkBBwIJAgcDCQMAAAAAyQ4QZBh2
CYzMWhX/ioY58dO4OCP3PJnZGPTY7fuVFkAmqTWExnJ1/jyohgtYagt8oY/JySc+NtiVnp1SSBmT
yW5WA6ytR8Eo8R5PkZ7o4ZCULg7OKgZm828SGQAAACAsy7WHA7UzeU3ZbTqSAqi6vNiNoxH7cd28
W46mz0UfF8KVBhgbCAAAADYFAmbzbxIiIQagtP65evBjWCEim+y6jdJcnOH0cSDTLc5PpWvo6gJJ
gwkQoLT+uXrwY1gCGwwAAAAAjRoQ96R96OJ9v5LANj7zanxgHiCii6MYYoI7O46O1iEMJj6qCxN9
u+rSk/m1dc6B7Xh3iCcDCrAsJeeRzZYmxTyX92iRGG5LN9K2SUZKZixQ8QzVGBs2zEdgqf76xwvE
4nrqGzMWaYMm8a7fXw==
=A0yl
-----END PGP PUBLIC KEY BLOCK-----
''';

  const curve448KeyData = '''
-----BEGIN PGP PUBLIC KEY BLOCK-----

xkMGZvNvExwAAAA5yWvpY7TWFFw8urr787Qb4cDyF9X59bJ6PjDvL2PoibX1jmU6Fuf30HSZnSLq
CAkvFx//A+rAbeEAwsA9Bh8cCgAAAFwFAmbzbxMiIQYwBf+MyThKw0UAWILFQZ6Yjv387mZGsM5P
Yn+mGyPc8QkQMAX/jMk4SsMCGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMCHgsNJwcBCQEHAgkCBwMJ
AwAAAAA6KyCR2q4SfxJ9R+ojCxLnpl3DLc4rjlEkmNzt9rYBMAb+mCjbwWsIn4Ez+w+CZKlAQ8dz
LMXjhfZGZXIBVJcZ6e+xKWDkJuX61YodNXwfpuEu9PpxfXNDbfIkgBz7M0eivjwaZwZyX8V4rGyc
+s87XomNPvrcSuW6cm1d3JcxCJ7rxPA4S+DTQcbThwerWlamgtALAM0qTmd1eWVuIFZhbiBOZ3V5
ZW4gPG5ndXllbm52MTk4MUBnbWFpbC5jb20+wsBABhAcCgAAAF8FAmbzbxMiIQYwBf+MyThKw0UA
WILFQZ6Yjv387mZGsM5PYn+mGyPc8QkQMAX/jMk4SsMCGwMDCwcJBCIBAgMFFQgMCg4FFgABAgMC
HgsNJwcBCQEHAgkCBwMJAwIZAQAAAADpZSCb+KoeU6eH6xbJQntrdR5qXdyuAbeGOVwSQLQeuMKk
+bcEigI/rGSWuAOX13KJdnOUrzNMlwkl3YdQ2Av956wbwYlmiukmHDFehyD3uBKegI4xpdDjiEXV
gH8+Vvus5ozRrjKqWtfulGfCNtL4e45x0gmqe1G80kK7QgTTfFwYbEhBMMczCPdlZliq9y0TJEwZ
AM0sTmd1eWVuIFZhbiBOZ3V5ZW4gPG5ndXllbm52QGl3YXl2aWV0bmFtLmNvbT7CwD0GEBwKAAAA
XAUCZvNvEyIhBjAF/4zJOErDRQBYgsVBnpiO/fzuZkawzk9if6YbI9zxCRAwBf+MyThKwwIbAwML
BwkEIgECAwUVCAwKDgUWAAECAwIeCw0nBwEJAQcCCQIHAwkDAAAAAPq1IEHDW8ZVfIDBR+pK4ogX
oxu7etsdcj8yXn44Uc1Pjo9gMbkRfTwnPJzGArJQ8lfDZtuOPxfLpstBQH3bBq3zV7mRVOdkvm24
8nXKCZsWWrVLdS/2P+PsFoAASiDURs8k7/mFtKvaSsJDkavtkwocXvqtUFgUguk2NiVVmIjZ3UvX
7U0YRbLVoDwtBzckoTzWRSUAzkIGZvNvExoAAAA4lrmeeMZwewtqqZ1VOJf7v9XXb5E6f7C58t1F
3V6CckIIYGG83tcM93nQSbVm0BtiBsKxH4LzOBnCwBcGGBwKAAAANgUCZvNvEyIhBjAF/4zJOErD
RQBYgsVBnpiO/fzuZkawzk9if6YbI9zxCRAwBf+MyThKwwIbDAAAAAAByyC9UL/ZIVdi+x90Vmme
eHW4+3472yq3PbVeLCsHnZQBWT8ocys2wRGxYnVuOUXvMiQJiMsIXJyW5zLf8/wH6jI0yS2aBazW
lohZO//dxuDMMuxa4YyCbhghAP9yUuW7NPeRQ3fPIjaUlORXdMyoallcsyhK3UGj90MWqStbJrvH
Cd9nlIA9bNiev1mPWeDKPpwaANUbud6PmWraXDt68RWZCEG9fzhJU0P61f/zRjXK
=/xA2
-----END PGP PUBLIC KEY BLOCK-----
''';

  print('Read RSA public key:');
  final rsaPublicKey = OpenPGP.readPublicKey(rsaKeyData);
  print('Key algorithm: ${rsaPublicKey.keyAlgorithm.name}');
  print('Key version: ${rsaPublicKey.version}');
  print('Key fingerprint: ${rsaPublicKey.fingerprint.toHexadecimal()}');
  for (final user in rsaPublicKey.users) {
    print('User ID: ${user.userID}');
  }

  print('\nRead Ecc public key:');
  final eccPublicKey = OpenPGP.readPublicKey(eccKeyData);
  print('Key algorithm: ${eccPublicKey.keyAlgorithm.name}');
  print('Key version: ${eccPublicKey.version}');
  print('Key fingerprint: ${eccPublicKey.fingerprint.toHexadecimal()}');
  for (final user in eccPublicKey.users) {
    print('User ID: ${user.userID}');
  }

  print('\nRead Curve25519 public key:');
  final curve25519PublicKey = OpenPGP.readPublicKey(curve25519KeyData);
  print('Key algorithm: ${curve25519PublicKey.keyAlgorithm.name}');
  print('Key version: ${curve25519PublicKey.version}');
  print('Key fingerprint: ${curve25519PublicKey.fingerprint.toHexadecimal()}');
  for (final user in curve25519PublicKey.users) {
    print('User ID: ${user.userID}');
  }

  print('\nRead Curve448 public key:');
  final curve448PublicKey = OpenPGP.readPublicKey(curve448KeyData);
  print('Key algorithm: ${curve448PublicKey.keyAlgorithm.name}');
  print('Key version: ${curve448PublicKey.version}');
  print('Key fingerprint: ${curve448PublicKey.fingerprint.toHexadecimal()}');
  for (var user in curve448PublicKey.users) {
    print('User ID: ${user.userID}');
  }

  print('\nMerge and armor public keys:');
  final armored = OpenPGP.armorPublicKeys([
    rsaPublicKey,
    eccPublicKey,
    curve25519PublicKey,
    curve448PublicKey,
  ]);
  final publicKeys = OpenPGP.readPublicKeys(armored);
  for (final publicKey in publicKeys) {
    print('\nKey algorithm: ${publicKey.keyAlgorithm.name}');
    print('Key version: ${publicKey.version}');
    print('Key fingerprint: ${publicKey.fingerprint.toHexadecimal()}');
    for (final user in publicKey.users) {
      print('User ID: ${user.userID}');
    }
  }
}
