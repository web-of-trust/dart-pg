import 'package:dart_pg/dart_pg.dart';

void main() {
  const text = 'Hello Dart PG!';
  const passphrase = 'secret stuff';
  const armoredPublicKeys = ['-----BEGIN PGP PUBLIC KEY BLOCK-----'];
  const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

  final publicKeys = armoredPublicKeys.map((armored) => OpenPGP.readPublicKey(armored));
  final privateKey = OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

  final encryptedMessage =
      OpenPGP.encrypt(Message.createTextMessage(text), encryptionKeys: publicKeys, signingKeys: [privateKey]);
  final encrypted = encryptedMessage.armor();
  print(encrypted);
}
