// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';
import 'package:pointycastle/key_generators/rsa_key_generator.dart';

import '../../helpers.dart';

/// Asymmetric block cipher using basic ElGamal algorithm.
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
  int get inputBlockSize => _forEncryption ? (_bitSize - 1) ~/ 8 : 2 * ((_bitSize + 7) >> 3);

  /// Return the maximum size for an output block to this engine.
  @override
  int get outputBlockSize => _forEncryption ? 2 * ((_bitSize + 7) >> 3) : (_bitSize - 1) ~/ 8;

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
    final int inLen,
    final Uint8List output,
    final int outOff,
  ) {
    if (_key == null) {
      throw StateError('$algorithmName not initialised');
    }

    final maxLength = _forEncryption ? (_bitSize - 1 + 7) ~/ 8 : inputBlockSize;
    if (inLen > maxLength) {
      throw ArgumentError('input too large for $algorithmName cipher.');
    }
    final prime = _key!.prime;

    if (_key is ElGamalPrivateKey) {
      /// decryption
      final gamma = input.sublist(0, inLen ~/ 2).toBigIntWithSign(1);
      final phi = input.sublist(inLen ~/ 2).toBigIntWithSign(1);

      final priv = _key as ElGamalPrivateKey;
      final m = (gamma.modPow(prime - (BigInt.one + priv.x), prime) * phi) % prime;
      output.setAll(outOff, m.toUnsignedBytes().sublist(0, output.length - outOff));
    } else {
      /// encryption
      final block = (inOff != 0 || inLen != input.length) ? input.sublist(0, inLen) : input;
      final inp = block.toBigIntWithSign(1);

      if (inp > prime) {
        throw ArgumentError('input too large for $algorithmName cipher.');
      }

      final k = _calculateK(prime);

      final pub = _key as ElGamalPublicKey;
      final gamma = pub.generator.modPow(k, prime);
      final phi = (inp * (pub.y.modPow(k, prime))) % prime;

      output.setAll(outOff, [
        ...gamma.toUnsignedBytes().sublist(0, outputBlockSize ~/ 2),
        ...phi.toUnsignedBytes().sublist(0, outputBlockSize ~/ 2),
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
    } while ((k == BigInt.zero) || (k.compareTo(n - BigInt.two) > 0));
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
      : publicKey = ElGamalPublicKey(generator.modPow(x, prime), prime, generator);

  BigInt get y => publicKey.y;
}

class ElGamalKeyGeneratorParameters extends KeyGeneratorParameters {
  final int certainty;

  ElGamalKeyGeneratorParameters(super.bitStrength, this.certainty);

  BigInt generatePrime(SecureRandom random) {
    final orderLength = bitStrength - 1;
    final minWeight = bitStrength >> 2;
    BigInt prime, order;
    for (;;) {
      order = generateProbablePrime(orderLength, certainty, random);
      prime = (order << 1) + BigInt.one;
      if (prime.isProbablePrime(certainty)) {
        continue;
      }
      if (certainty > 2 && !order.isProbablePrime(certainty - 2)) {
        continue;
      }
      if (prime.nafWeight < minWeight) {
        continue;
      }
      break;
    }
    return prime;
  }
}

class ElGamalKeyGenerator implements KeyGenerator {
  late SecureRandom _random;

  late ElGamalKeyGeneratorParameters _params;

  @override
  String get algorithmName => 'ElGamal';

  @override
  AsymmetricKeyPair<PublicKey, PrivateKey> generateKeyPair() {
    final prime = _params.generatePrime(_random);
    final generator = _selectGenerator(prime);
    final privateKey = ElGamalPrivateKey(_generatePrivateKey(0, prime), prime, generator);

    return AsymmetricKeyPair<PublicKey, PrivateKey>(privateKey.publicKey, privateKey);
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

  BigInt _selectGenerator(final BigInt prime) {
    BigInt generator;
    final primeMinusTwo = prime - BigInt.two;
    do {
      final h = Helper.randomBigIntInRange(BigInt.two, primeMinusTwo, random: _random);
      generator = h.modPow(BigInt.two, prime);
    } while (generator.compareTo(BigInt.one) == 0);
    return generator;
  }

  BigInt _generatePrivateKey(final int limit, final BigInt prime) {
    if (limit != 0) {
      int minWeight = limit >> 2;
      for (;;) {
        BigInt x = _random.nextBigInteger(limit - 1);
        if (x.nafWeight > minWeight) {
          return x;
        }
      }
    }
    BigInt max = prime - BigInt.two;
    int minWeight = max.bitLength >> 2;
    for (;;) {
      BigInt x = Helper.randomBigIntInRange(BigInt.two, max, random: _random);
      if (x.nafWeight > minWeight) {
        return x;
      }
    }
  }
}
