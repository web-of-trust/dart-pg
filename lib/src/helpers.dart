// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart' as pc;

import 'crypto/math/byte_ext.dart';
import 'crypto/math/int_ext.dart';
import 'enum/hash_algorithm.dart';
import 'enum/symmetric_algorithm.dart';

/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
extension StringHelper on String {
  List<String> chunk(final int chunkSize) {
    assert(chunkSize > 0);
    final chunkCount = (length / chunkSize).ceil();
    return List<String>.generate(chunkCount, (index) {
      final sliceStart = index * chunkSize;
      final sliceEnd = sliceStart + chunkSize;
      return substring(
        sliceStart,
        (sliceEnd < length) ? sliceEnd : length,
      );
    });
  }

  Uint8List hexToBytes() {
    final hex = replaceAll(RegExp(r'\s'), '');
    final result = Uint8List(hex.length ~/ 2);

    for (var i = 0; i < hex.length; i += 2) {
      final num = hex.substring(i, i + 2);
      final byte = int.parse(num, radix: 16);
      result[i ~/ 2] = byte;
    }

    return result;
  }

  Uint8List stringToBytes() => utf8.encoder.convert(this);

  bool hasMatch(final String text) => RegExp(this).hasMatch(text);
}

extension DateTimeHelper on DateTime {
  Uint8List toBytes() => (millisecondsSinceEpoch ~/ 1000).pack32();
}

class Helper {
  static final _random = Random.secure();

  static final _secureRandom = pc.SecureRandom('Fortuna')
    ..seed(
      pc.KeyParameter(
        Uint8List.fromList(
          List.generate(
            32,
            ((_) => _random.nextInt(0xffffffff)),
          ),
        ),
      ),
    );

  static BigInt readMPI(Uint8List bytes) {
    final bitLength = bytes.sublist(0, 2).toUint16();
    return bytes.sublist(2, ((bitLength + 7) >> 3) + 2).toBigIntWithSign(1);
  }

  static pc.SecureRandom secureRandom() => _secureRandom;

  static Uint8List generatePrefix([
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) {
    final prefix = _secureRandom.nextBytes(symmetric.blockSize);
    final repeat = [prefix[prefix.length - 2], prefix[prefix.length - 1]];
    return Uint8List.fromList([...prefix, ...repeat]);
  }

  static Uint8List generateEncryptionKey([
    final SymmetricAlgorithm symmetric = SymmetricAlgorithm.aes128,
  ]) =>
      _secureRandom.nextBytes((symmetric.keySize + 7) >> 3);

  static Uint8List hashDigest(
    final Uint8List input, [
    HashAlgorithm hash = HashAlgorithm.sha256,
  ]) {
    return pc.Digest(hash.digestName).process(input);
  }

  static BigInt randomBigInt(
    final BigInt min,
    final BigInt max, {
    pc.SecureRandom? random,
  }) {
    random = random ?? secureRandom();
    BigInt k;
    do {
      k = random.nextBigInteger(max.bitLength);
    } while (k.compareTo(min) <= 0 || k.compareTo(max) >= 0);
    return k;
  }
}
