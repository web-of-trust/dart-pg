import 'package:dart_pg/src/common/helpers.dart';
import 'package:dart_pg/src/openpgp.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  group('Sign cleartext', () {
    const cleartext = '''
What we need from the grocery store:

- tofu
- vegetables
- noodles
''';

    test('with key Bob', () {
      final signedMessage = OpenPGP.signCleartext(
        cleartext,
        [OpenPGP.readPrivateKey(bobPrivateKey)],
      );
      expect(signedMessage.text, cleartext);

      final verifications = OpenPGP.verify(
        signedMessage.armor(),
        [OpenPGP.readPublicKey(bobPublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'fbfcc82a015e7330');
      }
    });

    test('with key Alice', () {
      final signedMessage = OpenPGP.signCleartext(
        cleartext,
        [OpenPGP.readPrivateKey(alicePrivateKey)],
      );
      expect(signedMessage.text, cleartext);

      final verifications = OpenPGP.verify(
        signedMessage.armor(),
        [OpenPGP.readPublicKey(alicePublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'f231550c4f47e38e');
      }
    });

    test('with key from RFC9580', () {
      final signedMessage = OpenPGP.signCleartext(
        cleartext,
        [OpenPGP.readPrivateKey(rfc9580PrivateKey)],
      );
      expect(signedMessage.text, cleartext);

      final verifications = OpenPGP.verify(
        signedMessage.armor(),
        [OpenPGP.readPublicKey(rfc9580PublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'cb186c4f0609a697');
      }
    });
  });

  group('Verify signed message', () {
    test('with key Bob', () {
      const message = '''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

What we need from the grocery store:

- - tofu
- - vegetables
- - noodles

-----BEGIN PGP SIGNATURE-----

wsEhBAEBCABVBQJnUpraFiEE0aZuGiOxgsmYD3iM+/zIKgFeczAJEPv8yCoBXnMwLRQAAAAAABQA
EHNhbHRAcGhwLW9wZW5wZ3Aub3JnR92gUpKLIpx83AT82JIFkgAA73sMAFlDhrz3kOFgHu8Gde5J
nSdnjX4gePuqo9ftVOY5SpSqZoF5/msBiBDg0cxmhNcgt9YrYQghXXeW6/UVRN9EAdmgoc3IJH4+
0Zgx6t5FG5B3WlEkNhwaKqusyHPlqExUuYtNffFZr/Tq5fX6EYFm+TE4Wawv2iZ8QgqNMmLI2Yoo
DeE5lSWLugfs3N1u3sgUz2PmcRd400dIcUhVsxcC6ww1UV3busacRQ6SeitgaBKtr7SUnglSg4Wt
PT3WadAHhMHO7fN03uYHoFu782CQAzBxcYemF97muNKsM67krSgvUdOOusD0hl9LIyu+bQHTl8M6
FuK0heVyuKubvl7jZYjCIiPIeOMVhY/SFdUZsdS8PGCVWVeUi9fawg8GTnbZblDIOc6Lac388F5O
6Ud0juKDzzrQbcCXOl9eW5amAluyF2CusmcmoZIlATXvx/cU3Kj7+9UoayBJoZHLiwuiua9jiAS+
tzE+e1XVG0yeiFszkQzusP22sjen49qoDUPz6w==
-----END PGP SIGNATURE-----
''';
      final verifications = OpenPGP.verify(
        message,
        [OpenPGP.readPublicKey(bobPublicKey)],
      );
      for (final verification in verifications) {
        expect(verification.isVerified, isTrue);
        expect(verification.keyID.toHexadecimal(), 'fbfcc82a015e7330');
      }
    });

    test('with key Alice', () {
      const message = '''
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

What we need from the grocery store:

- - tofu
- - vegetables
- - noodles

-----BEGIN PGP SIGNATURE-----

wrMEARYKAGUFAmdSnJcWIQTrhbtfozp14V6UTmPyMVUMT0fjjgkQ8jFVDE9H4449FAAAAAAAFAAg
c2FsdEBwaHAtb3BlbnBncC5vcmd/HQUGqEXlSHw2e9ZyRojwCQQvt4Tzux4khKM9/8EulwAAd48B
AEwCfFc0o5a/pwjhd8VYv0VpSx6T6QoWesosqbOHZD+6AQA0w7TNC3TK+Ei+9+V83rC+9pMQlHbQ
IFe5XsSXLN9vBQ==
-----END PGP SIGNATURE-----
''';
      final verifications = OpenPGP.verify(
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
-----BEGIN PGP SIGNED MESSAGE-----

What we need from the grocery store:

- - tofu
- - vegetables
- - noodles

-----BEGIN PGP SIGNATURE-----

wpgGARsKAAAAKQWCY5ijYyIhBssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce6
2azJAAAAAGk2IHZJX1AhiJD39eLuPBgiUU9wUA9VHYblySHkBONKU/usJ9BvuAqo
/FvLFuGWMbKAdA+epq7V4HOtAPlBWmU8QOd6aud+aSunHQaaEJ+iTFjP2OMW0KBr
NK2ay45cX1IVAQ==
-----END PGP SIGNATURE-----
''';
      final verifications = OpenPGP.verify(
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
