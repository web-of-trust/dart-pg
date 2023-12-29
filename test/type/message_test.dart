import 'package:dart_pg/src/enum/compression_algorithm.dart';
import 'package:dart_pg/src/packet/compressed_data.dart';
import 'package:dart_pg/src/packet/public_key_encrypted_session_key.dart';
import 'package:dart_pg/src/packet/sym_encrypted_integrity_protected_data.dart';
import 'package:dart_pg/src/packet/sym_encrypted_session_key.dart';
import 'package:dart_pg/src/type/cleartext_message.dart';
import 'package:dart_pg/src/type/key.dart';
import 'package:dart_pg/src/type/message.dart';
import 'package:dart_pg/src/type/signed_message.dart';
import 'package:faker/faker.dart';
import 'package:test/test.dart';

import '../data/key_data.dart';

void main() {
  group('Cleartext signing', () {
    final signingKey = PrivateKey.fromArmored(privateKey);
    final verificationKey = PublicKey.fromArmored(publicKey);
    final text = faker.randomGenerator.string(1000);

    test('atached test', () async {
      final signedMessage = await SignedMessage.signCleartext(text, [signingKey]);
      final verifiedMessage = await signedMessage.verify([verificationKey]);
      final signature = signedMessage.signature;

      expect(signedMessage.verifications.isEmpty, isTrue);
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);

      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signature.packets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('detached test', () async {
      final signature =
          await SignedMessage.signCleartext(text, [signingKey]).then((signedMessage) => signedMessage.signature);
      final cleartextMessage = CleartextMessage(text);
      final verifiedMessage = await cleartextMessage.verifySignature(signature, [verificationKey]);

      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signature.packets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });
  });

  group('Message signing', () {
    final signingKey = PrivateKey.fromArmored(privateKey);
    final verificationKey = PublicKey.fromArmored(publicKey);
    final text = faker.randomGenerator.string(1000);

    test('atached test', () async {
      final signedMessage = await Message.createTextMessage(text).sign([signingKey]);
      expect(signedMessage.signingKeyIDs.elementAt(0).id, signingKey.keyID.id);
      expect(signedMessage.verifications.isEmpty, isTrue);

      final verifiedMessage = await signedMessage.verify([verificationKey]);
      final signaturePackets = signedMessage.signaturePackets;
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('detached test', () async {
      final message = Message.createTextMessage(text);
      final signature = await message.signDetached([signingKey]);
      final verifiedMessage = await message.verifySignature(signature, [verificationKey]);

      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signature.packets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });
  });

  group('Message compression', () {
    final text = faker.randomGenerator.string(1000);

    test('zip test', () async {
      final compressedMessage = await Message.createTextMessage(text).compress(CompressionAlgorithm.zip);
      expect(compressedMessage.packetList.length, 1);
      expect(compressedMessage.packetList.whereType<CompressedDataPacket>().elementAt(0).algorithm,
          CompressionAlgorithm.zip);

      final message = compressedMessage.unwrapCompressed();
      expect(message.packetList.whereType<CompressedDataPacket>(), isEmpty);
      expect(message.literalData, isNotNull);
      expect(message.literalData!.text, text);
    });

    test('zlib test', () async {
      final compressedMessage = await Message.createTextMessage(text).compress(CompressionAlgorithm.zlib);
      expect(compressedMessage.packetList.length, 1);
      expect(compressedMessage.packetList.whereType<CompressedDataPacket>().elementAt(0).algorithm,
          CompressionAlgorithm.zlib);

      final message = compressedMessage.unwrapCompressed();
      expect(message.packetList.whereType<CompressedDataPacket>(), isEmpty);
      expect(message.literalData, isNotNull);
      expect(message.literalData!.text, text);
    });

    test('bzip2 test', () {
      expect(
        () => Message.createTextMessage(text).compress(CompressionAlgorithm.bzip2),
        throwsUnsupportedError,
      );
    });
  });

  group('Message encryption', () {
    final signingKey = PrivateKey.fromArmored(privateKey);
    final verificationKey = PublicKey.fromArmored(publicKey);
    final encryptionKeys = [
      PublicKey.fromArmored(rsaPublicKey),
      PublicKey.fromArmored(dsaPublicKey),
      PublicKey.fromArmored(eccPublicKey),
      PublicKey.fromArmored(curve25519PublicKey),
    ];
    final password = faker.randomGenerator.string(100);

    final text = faker.randomGenerator.string(1000);
    final createTextMessage = Message.createTextMessage(text);
    final signedMessage = createTextMessage.sign([signingKey]);
    final encryptedMessage = signedMessage.then(
      (signedMessage) => signedMessage.encrypt(encryptionKeys: encryptionKeys, passwords: [password]),
    );

    test('encrypted test', () {
      encryptedMessage.then((message) {
        expect(message.literalData, isNull);
        expect(message.packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().length, encryptionKeys.length);
        expect(message.packetList.whereType<SymEncryptedSessionKeyPacket>().length, 1);
        expect(message.packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>(), isNotEmpty);
      });
    });

    test('password only test', () async {
      final encryptedMessage = await createTextMessage.encrypt(passwords: [password]);
      expect(encryptedMessage.literalData, isNull);
      expect(encryptedMessage.packetList.whereType<SymEncryptedSessionKeyPacket>(), isNotEmpty);
      expect(encryptedMessage.packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>(), isNotEmpty);

      final decryptedMessage = await encryptedMessage.decrypt(passwords: [password]);
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);
    });

    test('password decrypt test', () async {
      final decryptedMessage = await encryptedMessage.then((message) => message.decrypt(passwords: [password]));
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = await decryptedMessage.verify([verificationKey]);
      final signaturePackets = await signedMessage.then((signedMessage) => signedMessage.signaturePackets);
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('rsa decrypt test', () async {
      final decryptionKey = await PrivateKey.fromArmored(rsaPrivateKey).decrypt(passphrase);
      final decryptedMessage =
          await encryptedMessage.then((message) => message.decrypt(decryptionKeys: [decryptionKey]));
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = await decryptedMessage.verify([verificationKey]);
      final signaturePackets = await signedMessage.then((signedMessage) => signedMessage.signaturePackets);
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('elgamal decrypt test', () async {
      final decryptionKey = await PrivateKey.fromArmored(dsaPrivateKey).decrypt(passphrase);
      final decryptedMessage =
          await encryptedMessage.then((message) => message.decrypt(decryptionKeys: [decryptionKey]));
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = await decryptedMessage.verify([verificationKey]);
      final signaturePackets = await signedMessage.then((signedMessage) => signedMessage.signaturePackets);
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('ecc decrypt test', () async {
      final decryptionKey = await PrivateKey.fromArmored(eccPrivateKey).decrypt(passphrase);
      final decryptedMessage =
          await encryptedMessage.then((message) => message.decrypt(decryptionKeys: [decryptionKey]));
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = await decryptedMessage.verify([verificationKey]);
      final signaturePackets = await signedMessage.then((signedMessage) => signedMessage.signaturePackets);
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('curve25519 decrypt test', () async {
      final decryptionKey = await PrivateKey.fromArmored(curve25519PrivateKey).decrypt(passphrase);
      final decryptedMessage =
          await encryptedMessage.then((message) => message.decrypt(decryptionKeys: [decryptionKey]));
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = await decryptedMessage.verify([verificationKey]);
      final signaturePackets = await signedMessage.then((signedMessage) => signedMessage.signaturePackets);
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.id);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('decrypt aead message test', () async {
      const encryptedMessageData = '''
-----BEGIN PGP MESSAGE-----

jD0FBwIDCBt851vLHmcX/6vdNoPTtUfAzChVu81xM5XTozdap+0i087ojXBfNnI+
E8PyCSTHDlgN4vWJzBS+1E0BBwIQCicPh3seliAmtmPxL4M/qEj7bIX0kgtygRa3
g68tHRXcVN6USJbvuTWuIwy8eaCwrRdG3pF3b5BADyHl3nsINR9KysPKuM1AaQ==
=STC7
-----END PGP MESSAGE-----
''';
      final decryptedMessage = await Message.fromArmored(encryptedMessageData).decrypt(passwords: ['password']);
      expect(decryptedMessage.literalData!.text, "Hello Dart PG\n");
    });
  });
}
