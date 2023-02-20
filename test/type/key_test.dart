import 'package:dart_pg/src/enums.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:test/test.dart';

import '../test_data.dart';

void main() {
  group('A group of tests', () {
    test('RSA public key', () {
      final publicKey = PublicKey.fromArmored(rsaPublicKey);

      expect(publicKey.fingerprint, '44ebf9e6dc6647d61c556de27a686b5a10709559');
      expect(publicKey.algorithm, KeyAlgorithm.rsaEncryptSign);
      expect(publicKey.isPrivate, false);

      final user = publicKey.users[0];
      expect(user.userID!.name, 'rsa pgp key');
      expect(user.userID!.email, 'test@dummy.com');
      expect(user.verify(publicKey.keyPacket), isTrue);

      final subkey = publicKey.subkeys[0];
      subkey.verify(publicKey.keyPacket);
    });
  });
}
