// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/export.dart';

import '../../helpers.dart';
import '../math/big_int.dart';
import '../math/byte_ext.dart';

/// Asymmetric block cipher using basic ElGamal algorithm.
/// Ported and modified from Bouncy Castle project
class ElGamalEngine implements AsymmetricBlockCipher {
  late ElGamalAsymmetricKey? _key;

  late SecureRandom _random;

  bool _forEncryption = false;

  late int _bitSize;

  @override
  String get algorithmName => 'ElGamal';

  @override
  void init(final bool forEncryption, CipherParameters params) {
    _forEncryption = forEncryption;
    if (params is ParametersWithRandom) {
      _random = params.random;
      params = params.parameters;
    } else {
      _random = Helper.secureRandom();
    }
    if (params is AsymmetricKeyParameter<ElGamalAsymmetricKey>) {
      _key = params.key;
      _bitSize = _key!.prime.bitLength;

      if (_forEncryption) {
        if (_key is! ElGamalPublicKey) {
          throw ArgumentError('Encryption requires public key.');
        }
      } else {
        if (_key is! ElGamalPrivateKey) {
          throw ArgumentError('Decryption requires private key.');
        }
      }
    } else {
      throw ArgumentError('ElGamalKeyParameters are required.');
    }
  }

  /// Return the maximum size for an input block to this engine.
  @override
  int get inputBlockSize =>
      _forEncryption ? (_bitSize - 1) ~/ 8 : 2 * ((_bitSize + 7) >> 3);

  /// Return the maximum size for an output block to this engine.
  @override
  int get outputBlockSize =>
      _forEncryption ? 2 * ((_bitSize + 7) >> 3) : (_bitSize - 1) ~/ 8;

  @override
  Uint8List process(final Uint8List data) {
    final out = Uint8List(outputBlockSize);
    final len = processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

  /// Process a single block using the basic ElGamal algorithm.
  @override
  int processBlock(
    final Uint8List input,
    final int inOff,
    final int inLength,
    final Uint8List output,
    final int outOff,
  ) {
    if (_key == null) {
      throw StateError('$algorithmName not initialised');
    }

    final maxLength = _forEncryption ? (_bitSize - 1 + 7) ~/ 8 : inputBlockSize;
    if (inLength > maxLength) {
      throw ArgumentError('input too large for $algorithmName cipher.');
    }
    final prime = _key!.prime;

    if (_key is ElGamalPrivateKey) {
      /// decryption
      final gamma = input.sublist(0, inLength ~/ 2).toBigIntWithSign(1);
      final phi = input.sublist(inLength ~/ 2).toBigIntWithSign(1);

      final priv = _key as ElGamalPrivateKey;
      final m =
          (gamma.modPow(prime - (BigInt.one + priv.x), prime) * phi) % prime;
      output.setAll(
        outOff,
        m.toUnsignedBytes().sublist(0, output.length - outOff),
      );
    } else {
      /// encryption
      final block = (inOff != 0 || inLength != input.length)
          ? input.sublist(0, inLength)
          : input;
      final inp = block.toBigIntWithSign(1);

      if (inp > prime) {
        throw ArgumentError('input too large for $algorithmName cipher.');
      }

      final byteLength = outputBlockSize ~/ 2;
      final pub = _key as ElGamalPublicKey;
      BigInt gamma, phi;
      do {
        final k = _calculateK(prime);

        gamma = pub.generator.modPow(k, prime);
        phi = (inp * (pub.y.modPow(k, prime))) % prime;
      } while (gamma.byteLength < byteLength || phi.byteLength < byteLength);

      output.setAll(outOff, [
        ...gamma.toUnsignedBytes().sublist(0, byteLength),
        ...phi.toUnsignedBytes().sublist(0, byteLength),
      ]);
    }

    return output.length;
  }

  @override
  void reset() {}

  BigInt _calculateK(final BigInt n) {
    BigInt k;
    do {
      k = _random.nextBigInteger(n.bitLength);
    } while ((k.sign == 0) || (k.compareTo(n - BigInt.two) > 0));
    return k;
  }
}

abstract class ElGamalAsymmetricKey implements AsymmetricKey {
  /// prime
  final BigInt prime;

  /// group generator
  final BigInt generator;

  ElGamalAsymmetricKey(this.prime, this.generator);
}

class ElGamalPublicKey extends ElGamalAsymmetricKey implements PublicKey {
  /// public exponent y = g ** x mod p
  final BigInt y;

  ElGamalPublicKey(this.y, super.prime, super.generator);
}

class ElGamalPrivateKey extends ElGamalAsymmetricKey implements PrivateKey {
  /// secret exponent
  final BigInt x;

  /// public key
  final ElGamalPublicKey publicKey;

  ElGamalPrivateKey(this.x, super.prime, super.generator)
      : publicKey = ElGamalPublicKey(
          generator.modPow(x, prime),
          prime,
          generator,
        );

  BigInt get y => publicKey.y;
}

class ElGamalKeyGeneratorParameters extends KeyGeneratorParameters {
  final int size;

  final int certainty;

  ElGamalKeyGeneratorParameters(super.bitStrength, this.size, this.certainty);

  Map<String, BigInt> generateParameters(final SecureRandom random) {
    BigInt prime, generator;

    final order = generateProbablePrime(size, 1, random);
    final divisor = order * BigInt.two;
    do {
      final x = random.nextBigInteger(bitStrength);
      final c = x % divisor;
      prime = x - (c - BigInt.one);
    } while (
        !prime.isProbablePrime(certainty) || prime.bitLength != bitStrength);

    final p2 = prime - BigInt.two;
    do {
      final h = Helper.randomBigInt(BigInt.two, p2, random: random);
      generator = h.modPow(BigInt.two, prime);
    } while (generator.compareTo(BigInt.one) == 0);

    return {
      'prime': prime,
      'generator': generator,
    };
  }
}

class ElGamalKeyGenerator implements KeyGenerator {
  late SecureRandom _random;

  late ElGamalKeyGeneratorParameters _params;

  @override
  String get algorithmName => 'ElGamal';

  @override
  AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair() {
    final params = _params.generateParameters(_random);
    final prime = params['prime']!;
    final generator = params['generator']!;
    final privateKey = ElGamalPrivateKey(
      _generateSecretExponent(_params.size, prime),
      prime,
      generator,
    );

    return AsymmetricKeyPair<PublicKey, PrivateKey>(
      privateKey.publicKey,
      privateKey,
    );
  }

  @override
  void init(CipherParameters params) {
    if (params is ParametersWithRandom) {
      _random = params.random;
      _params = params.parameters as ElGamalKeyGeneratorParameters;
    } else {
      _random = Helper.secureRandom();
      _params = params as ElGamalKeyGeneratorParameters;
    }
  }

  BigInt _generateSecretExponent(final int size, final BigInt prime) {
    if (size != 0) {
      final minWeight = size >> 2;
      for (;;) {
        BigInt x = _random.nextBigInteger(size - 1);
        if (x.nafWeight > minWeight) {
          return x;
        }
      }
    }
    final max = prime - BigInt.two;
    final minWeight = max.bitLength >> 2;
    for (;;) {
      BigInt x = Helper.randomBigInt(BigInt.two, max, random: _random);
      if (x.nafWeight > minWeight) {
        return x;
      }
    }
  }
}
