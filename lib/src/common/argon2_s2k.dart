/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import '../enum/s2k_type.dart';
import '../type/s2k.dart';
import 'helpers.dart';

/// Implementation of the Argon2 string-to-key specifier
/// See https://www.rfc-editor.org/rfc/rfc9580#section-3.7
class Argon2S2k implements S2kInterface {
  /// Default salt length
  static const saltLength = 16;

  @override
  final Uint8List salt;

  /// Number of iterations
  final int iteration;

  /// Number of parallel threads
  final int parallelism;

  /// The exponent of the memory size
  final int memoryExponent;

  Argon2S2k(
    this.salt, [
    this.iteration = Argon2Parameters.DEFAULT_ITERATIONS,
    this.parallelism = Argon2Parameters.DEFAULT_LANES,
    this.memoryExponent = Argon2Parameters.DEFAULT_MEMORY_COST,
  ]);

  /// Parsing function for a string-to-key specifier
  factory Argon2S2k.fromBytes(final Uint8List bytes) {
    var pos = 1;
    final salt = bytes.sublist(pos, pos + saltLength);
    pos += saltLength;
    final iteration = bytes[pos++];
    final parallelism = bytes[pos++];
    final memoryExponent = bytes[pos++];
    return Argon2S2k(
      salt,
      iteration,
      parallelism,
      memoryExponent,
    );
  }

  @override
  produceKey(String passphrase, int length) {
    final gen = Argon2BytesGenerator()
      ..init(Argon2Parameters(
        Argon2Parameters.ARGON2_id,
        salt,
        desiredKeyLength: length,
        iterations: iteration,
        lanes: parallelism,
        memoryPowerOf2: memoryExponent,
      ));
    return gen.process(passphrase.toBytes());
  }

  @override
  get length => type.length;

  @override
  get toBytes => Uint8List.fromList([
        type.value,
        ...salt,
        iteration,
        parallelism,
        memoryExponent,
      ]);

  @override
  get type => S2kType.argon2;
}
