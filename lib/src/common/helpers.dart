/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import 'argon2_s2k.dart';
import 'extensions.dart';
import 'generic_s2k.dart';
import '../type/s2k.dart';
import '../enum/s2k_type.dart';
import '../enum/hash_algorithm.dart';
import '../enum/symmetric_algorithm.dart';

export 'extensions.dart';

/// Helper class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Helper {
  static final _random = Random.secure();

  static final _secureRandom = SecureRandom('Fortuna')
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

  static BigInt readMPI(final Uint8List bytes) {
    final bitLength = bytes.sublist(0, 2).unpack16();
    return bytes.sublist(2, ((bitLength + 7) >> 3) + 2).toBigIntWithSign(1);
  }

  static SecureRandom secureRandom() => _secureRandom;

  static Uint8List generatePrefix([
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    final prefix = _secureRandom.nextBytes(symmetric.blockSize);
    return Uint8List.fromList([
      ...prefix,
      prefix[prefix.length - 2],
      prefix[prefix.length - 1],
    ]);
  }

  static Uint8List generateEncryptionKey([
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) =>
      _secureRandom.nextBytes((symmetric.keySize + 7) >> 3);

  static Uint8List hashDigest(
    final Uint8List input, [
    final HashAlgorithm hash = HashAlgorithm.sha256,
  ]) {
    return Digest(hash.digestName).process(input);
  }

  static BigInt randomBigInt(
    final BigInt min,
    final BigInt max, {
    SecureRandom? random,
  }) {
    random = random ?? secureRandom();
    BigInt k;
    do {
      k = random.nextBigInteger(max.bitLength);
    } while (k.compareTo(min) <= 0 || k.compareTo(max) >= 0);
    return k;
  }

  static S2kInterface stringToKey(final S2kType type) {
    assert(type != S2kType.simple);
    return switch (type) {
      S2kType.argon2 => Argon2S2k(
          _secureRandom.nextBytes(Argon2S2k.saltLength),
        ),
      _ => GenericS2k(
          _secureRandom.nextBytes(Argon2S2k.saltLength),
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
    assert(hash != HashAlgorithm.md5 && hash != HashAlgorithm.sha1 && hash != HashAlgorithm.ripemd160);
  }

  static assertSymmetric(final SymmetricAlgorithm symmetric) {
    assert(symmetric != SymmetricAlgorithm.plaintext &&
        symmetric != SymmetricAlgorithm.cast5 &&
        symmetric != SymmetricAlgorithm.idea &&
        symmetric != SymmetricAlgorithm.tripledes);
  }
}
