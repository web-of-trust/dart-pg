/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import '../type/s2k.dart';
import '../enum/s2k_type.dart';
import '../enum/hash_algorithm.dart';
import '../enum/symmetric_algorithm.dart';
import 'argon2_s2k.dart';
import 'extensions.dart';
import 'generic_s2k.dart';

export 'extensions.dart';

/// Helper class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Helper {
  static final _random = Random.secure();

  static SecureRandom get secureRandom => SecureRandom('Fortuna')
    ..seed(
      KeyParameter(
        Uint8List.fromList(
          List.generate(
            32,
            ((_) => _random.nextInt(0xffffffff)),
          ),
        ),
      ),
    );

  static BigInt readMPI(final Uint8List bytes) => bytes
      .sublist(
        2,
        ((bytes.sublist(0, 2).unpack16() + 7) >> 3) + 2,
      )
      .toBigIntWithSign(1);

  static Uint8List generatePrefix([
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    final prefix = randomBytes(symmetric.blockSize);
    return Uint8List.fromList([
      ...prefix,
      prefix[prefix.length - 2],
      prefix[prefix.length - 1],
    ]);
  }

  static Uint8List generateEncryptionKey([
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) =>
      randomBytes((symmetric.keySize + 7) >> 3);

  static Uint8List hashDigest(
    final Uint8List input, [
    final HashAlgorithm hash = HashAlgorithm.sha256,
  ]) =>
      Digest(hash.digestName).process(input);

  static String generatePassword([final int length = 32]) => List.generate(
        length,
        ((_) => _random.nextInt(126 - 40) + 40),
      ).map((char) => String.fromCharCode(char)).join();

  static Uint8List randomBytes(final int length) => secureRandom.nextBytes(
        length,
      );

  static BigInt randomBigInt(final BigInt min, final BigInt max) {
    BigInt k;
    do {
      k = secureRandom.nextBigInteger(max.bitLength);
    } while (k.compareTo(min) <= 0 || k.compareTo(max) >= 0);
    return k;
  }

  static int randomInt(
    final int min,
    final int max,
  ) =>
      _random.nextInt(max - min) + min;

  static S2kInterface stringToKey(final S2kType type) {
    assert(type != S2kType.simple);
    return switch (type) {
      S2kType.argon2 => Argon2S2k(
          randomBytes(Argon2S2k.saltLength),
        ),
      _ => GenericS2k(
          randomBytes(GenericS2k.saltLength),
        ),
    };
  }

  /// Generate a HKDF key derivation of a supplied key input
  static Uint8List hkdf(
    final Uint8List key,
    final int length, {
    final HashAlgorithm hash = HashAlgorithm.sha256,
    final Uint8List? salt,
    final Uint8List? info,
  }) {
    final params = HkdfParameters(
      key,
      length,
      salt,
      info,
    );
    final hkdf = HKDFKeyDerivator(Digest(hash.digestName));
    hkdf.init(params);
    final derivedKey = Uint8List(length);
    hkdf.deriveKey(null, 0, derivedKey, 0);
    return derivedKey;
  }

  static assertHash(final HashAlgorithm hash) {
    switch (hash) {
      case HashAlgorithm.unknown:
      case HashAlgorithm.md5:
      case HashAlgorithm.sha1:
      case HashAlgorithm.ripemd160:
        throw UnsupportedError(
          'Hash ${hash.name} is unsupported.',
        );
      default:
    }
  }

  static assertSymmetric(final SymmetricAlgorithm symmetric) {
    if (!SymmetricAlgorithm.preferredSymmetrics.contains(symmetric)) {
      throw UnsupportedError(
        'Symmetric ${symmetric.name} is unsupported.',
      );
    }
  }
}
