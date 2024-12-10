import 'package:dart_pg/dart_pg.dart';

void main() {
  const userIDs = [
    'Dart Privacy Guard <dartpg@openpgp.example.com>',
    'Nguyen Van Nguyen <nguyennv1981@gmail.com>',
  ];
  final passphrase = Helper.generatePassword();
  print('Generate passphase: $passphrase');

  print('Generate RSA private key:');
  final rsaPrivateKey = OpenPGP.generateKey(
    userIDs,
    passphrase,
    type: KeyType.rsa,
    rsaKeySize: RSAKeySize.normal,
  );
  print(rsaPrivateKey.armor());

  print('Generate Ecc private key:');
  final eccPrivateKey = OpenPGP.generateKey(
    userIDs,
    passphrase,
    type: KeyType.ecc,
    curve: Ecc.secp521r1,
  );
  print(eccPrivateKey.armor());

  print('Generate Curve25519 private key:');
  final curve25519PrivateKey = OpenPGP.generateKey(
    userIDs,
    passphrase,
    type: KeyType.curve25519,
  );
  print(curve25519PrivateKey.armor());

  print('Generate Curve448 private key:');
  final curve448PrivateKey = OpenPGP.generateKey(
    userIDs,
    passphrase,
    type: KeyType.curve448,
  );
  print(curve448PrivateKey.armor());
}
