import 'package:dart_pg/dart_pg.dart';

Future<void> main() async {
  const text = 'Hello Dart PG!';
  const passphrase = 'secret stuff';
  const armoredPublicKeys = ['-----BEGIN PGP PUBLIC KEY BLOCK-----'];
  const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';

  final publicKeys = await Future.wait(
    armoredPublicKeys.map((armored) => OpenPGP.readPublicKey(armored)),
  );
  final privateKey = await OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

  final encryptedMessage =
      await OpenPGP.encrypt(Message.createTextMessage(text), encryptionKeys: publicKeys, signingKeys: [privateKey]);
  final encrypted = encryptedMessage.armor();
  print(encrypted);
}
