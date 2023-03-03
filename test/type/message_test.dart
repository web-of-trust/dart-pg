import 'package:dart_pg/src/enums.dart';
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

import '../test_data.dart';

void main() {
  group('Cleartext signing', () {
    final signingKey = PrivateKey.fromArmored(privateKey);
    final verificationKey = PublicKey.fromArmored(publicKey);
    final text = faker.randomGenerator.string(1000);

    test('atached test', () {
      final signedMessage = SignedMessage.signCleartext(text, [signingKey]);
      final verifiedMessage = signedMessage.verify([verificationKey]);
      final signature = signedMessage.signature;

      expect(signedMessage.verifications.isEmpty, isTrue);
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);

      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signature.packets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('detached test', () {
      final signature = SignedMessage.signCleartext(text, [signingKey]).signature;
      final cleartextMessage = CleartextMessage(text);
      final verifiedMessage = cleartextMessage.verifySignature(signature, [verificationKey]);

      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
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

    test('atached test', () {
      final signedMessage = Message.createTextMessage(text).sign([signingKey]);
      expect(signedMessage.signingKeyIDs.elementAt(0).keyID, signingKey.keyID.keyID);
      expect(signedMessage.verifications.isEmpty, isTrue);

      final verifiedMessage = signedMessage.verify([verificationKey]);
      final signaturePackets = signedMessage.signaturePackets;
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('detached test', () {
      final message = Message.createTextMessage(text);
      final signature = message.signDetached([signingKey]);
      final verifiedMessage = message.verifySignature(signature, [verificationKey]);

      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
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

    test('zip test', () {
      final compressedMessage = Message.createTextMessage(text).compress(CompressionAlgorithm.zip);
      expect(compressedMessage.packetList.length, 1);
      expect(compressedMessage.packetList.whereType<CompressedDataPacket>().elementAt(0).algorithm,
          CompressionAlgorithm.zip);

      final message = compressedMessage.unwrapCompressed();
      expect(message.packetList.whereType<CompressedDataPacket>(), isEmpty);
      expect(message.literalData, isNotNull);
      expect(message.literalData!.text, text);
    });

    test('zlib test', () {
      final compressedMessage = Message.createTextMessage(text).compress(CompressionAlgorithm.zlib);
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
    ];
    final password = faker.randomGenerator.string(100);

    final text = faker.randomGenerator.string(1000);
    final createTextMessage = Message.createTextMessage(text);
    final signedMessage = createTextMessage.sign([signingKey]);
    final encryptedMessage = signedMessage.encrypt(encryptionKeys: encryptionKeys, passwords: [password]);

    test('encrypted test', () {
      expect(encryptedMessage.literalData, isNull);
      expect(encryptedMessage.packetList.whereType<PublicKeyEncryptedSessionKeyPacket>().length, encryptionKeys.length);
      expect(encryptedMessage.packetList.whereType<SymEncryptedSessionKeyPacket>().length, 1);
      expect(encryptedMessage.packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>(), isNotEmpty);
    });

    test('password only test', () {
      final encryptedMessage = createTextMessage.encrypt(passwords: [password]);
      expect(encryptedMessage.literalData, isNull);
      expect(encryptedMessage.packetList.whereType<SymEncryptedSessionKeyPacket>(), isNotEmpty);
      expect(encryptedMessage.packetList.whereType<SymEncryptedIntegrityProtectedDataPacket>(), isNotEmpty);

      final decryptedMessage = encryptedMessage.decrypt(passwords: [password]);
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);
    });

    test('password decrypt test', () {
      final decryptedMessage = encryptedMessage.decrypt(passwords: [password]);
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = decryptedMessage.verify([verificationKey]);
      final signaturePackets = signedMessage.signaturePackets;
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('rsa decrypt test', () {
      final decryptionKey = PrivateKey.fromArmored(rsaPrivateKey).decrypt(passphrase);
      final decryptedMessage = encryptedMessage.decrypt(decryptionKeys: [decryptionKey]);
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = decryptedMessage.verify([verificationKey]);
      final signaturePackets = signedMessage.signaturePackets;
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('elgamal decrypt test', () {
      final decryptionKey = PrivateKey.fromArmored(dsaPrivateKey).decrypt(passphrase);
      final decryptedMessage = encryptedMessage.decrypt(decryptionKeys: [decryptionKey]);
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = decryptedMessage.verify([verificationKey]);
      final signaturePackets = signedMessage.signaturePackets;
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });

    test('ecc decrypt test', () {
      final decryptionKey = PrivateKey.fromArmored(eccPrivateKey).decrypt(passphrase);
      final decryptedMessage = encryptedMessage.decrypt(decryptionKeys: [decryptionKey]);
      expect(decryptedMessage.literalData, isNotNull);
      expect(decryptedMessage.literalData!.text, text);

      final verifiedMessage = decryptedMessage.verify([verificationKey]);
      final signaturePackets = signedMessage.signaturePackets;
      expect(verifiedMessage.verifications.isNotEmpty, isTrue);
      for (final verification in verifiedMessage.verifications) {
        expect(verification.keyID, verificationKey.keyID.keyID);
        expect(verification.verified, isTrue);

        expect(
          signaturePackets.elementAt(0).signatureData,
          equals(verification.signature.packets.elementAt(0).signatureData),
        );
      }
    });
  });
}
