import 'package:dart_pg/dart_pg.dart';

Future<void> main() async {
  const passphrase = 'secret stuff';
  const armoredPublicKey = '-----BEGIN PGP PUBLIC KEY BLOCK-----';
  const armoredPrivateKey = '-----BEGIN PGP PRIVATE KEY BLOCK-----';
  const armoredMessage = '';

  final publicKey = await OpenPGP.readPublicKey(armoredPublicKey);
  final privateKey = await OpenPGP.decryptPrivateKey(armoredPrivateKey, passphrase);

  final decryptedMessage = await OpenPGP.decrypt(
    await OpenPGP.readMessage(armoredMessage),
    decryptionKeys: [privateKey],
    verificationKeys: [publicKey],
  );
  final verifications = decryptedMessage.verifications;
  print(verifications);
}
