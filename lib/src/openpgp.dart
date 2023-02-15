// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'enums.dart';
import 'packet/contained_packet.dart';
import 'packet/key_packet_generator.dart';
import 'packet/packet_list.dart';
import 'packet/signature_generator.dart';
import 'packet/user_id.dart';
import 'type/cleartext_message.dart';
import 'type/private_key.dart';

class OpenPGP {
  static const version = 'Dart Privacy Guard 1.0.0';

  static const comment = 'Dart Privacy Guard';

  static const showVersion = true;

  static const showComment = false;

  static const checksumRequired = true;

  static const version5Keys = false;

  /// Default hash algorithm
  static const preferredHashAlgorithm = HashAlgorithm.sha256;

  /// Default encryption cipher
  static const preferredSymmetricAlgorithm = SymmetricAlgorithm.aes256;

  static const preferredCurve = CurveInfo.brainpoolp512r1;

  /// Default RSA bits length
  static const preferredRSABits = 4096;

  /// Min RSA bits length
  static const minRSABits = 2048;

  /// RSA public exponent
  static const rsaPublicExponent = '65537';

  static signDetached(String message, List<PrivateKey> signingKeys) {}

  static sign(
    CleartextMessage message,
    List<PrivateKey> signingKeys, {
    DateTime? date,
    bool detached = false,
  }) {
    if (signingKeys.isEmpty) {
      throw Exception('No signing keys provided');
    }
  }

  static PrivateKey generateKey(
    List<String> userIDs,
    String passphrase, {
    KeyType type = KeyType.rsa,
    int rsaBits = OpenPGP.preferredRSABits,
    CurveInfo curve = OpenPGP.preferredCurve,
    int keyExpirationTime = 0,
    bool subkeySign = false,
    String? subkeyPassphrase,
    DateTime? date,
  }) {
    if (userIDs.isEmpty) {
      throw Exception('UserIDs are required for key generation');
    }

    final keyAlgorithm = (type == KeyType.rsa) ? KeyAlgorithm.rsaEncryptSign : KeyAlgorithm.ecdsa;
    final subkeyAlgorithm = (type == KeyType.rsa) ? KeyAlgorithm.rsaEncryptSign : KeyAlgorithm.ecdh;

    final secretKey = KeyPacketGenerator.generateSecretKey(
      keyAlgorithm,
      rsaBits: rsaBits,
      curve: curve,
      date: date,
    ).encrypt(passphrase);
    final secretSubkey = KeyPacketGenerator.generateSecretSubkey(
      subkeyAlgorithm,
      rsaBits: rsaBits,
      curve: curve,
      date: date,
    ).encrypt(subkeyPassphrase ?? passphrase);

    final packets = <ContainedPacket>[secretKey];

    /// Wrap user id with certificate signature
    for (final userID in userIDs) {
      final userIDPacket = UserIDPacket(userID);
      packets.addAll([
        userIDPacket,
        SignatureGenerator.createCertificateSignature(
          userIDPacket,
          secretKey,
          keyExpirationTime: keyExpirationTime,
          date: date,
        )
      ]);
    }

    /// Wrap secret subkey with binding signature
    packets.addAll([
      secretSubkey,
      SignatureGenerator.createBindingSignature(
        secretSubkey,
        secretKey,
        keyExpirationTime: keyExpirationTime,
        subkeySign: subkeySign,
        date: date,
      ),
    ]);

    /// Add revocation signature packet for creating a revocation certificate.
    packets.add(SignatureGenerator.createRevocationSignature(
      secretKey,
      date: date,
    ));

    return PrivateKey.fromPacketList(PacketList(packets));
  }
}
