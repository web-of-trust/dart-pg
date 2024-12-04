/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:typed_data';
import 'package:pointycastle/api.dart';

import '../../common/helpers.dart';

/// Asymmetric block cipher using basic ElGamal algorithm.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class ElGamalEngine implements AsymmetricBlockCipher {
  late ElGamalAsymmetricKey? _key;

  late SecureRandom _random;

  bool _forEncryption = false;

  late int _bitSize;

  @override
  get algorithmName => 'ElGamal';

  @override
  init(final bool forEncryption, CipherParameters params) {
    _forEncryption = forEncryption;
    if (params is ParametersWithRandom) {
      _random = params.random;
      params = params.parameters;
    } else {
      _random = Helper.secureRandom;
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
  get inputBlockSize => _forEncryption ? (_bitSize - 1) ~/ 8 : 2 * ((_bitSize + 7) >> 3);

  /// Return the maximum size for an output block to this engine.
  @override
  get outputBlockSize => _forEncryption ? 2 * ((_bitSize + 7) >> 3) : (_bitSize - 1) ~/ 8;

  @override
  process(final Uint8List data) {
    final out = Uint8List(outputBlockSize);
    final len = processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

  /// Process a single block using the basic ElGamal algorithm.
  @override
  processBlock(
    final Uint8List input,
    final int inOff,
    final int inLength,
    final Uint8List output,
    final int outOff,
  ) {
    if (_key == null) {
      throw StateError('$algorithmName not initialised');
    }

    if (inLength > inputBlockSize) {
      throw ArgumentError('Input too large for $algorithmName cipher.');
    }
    final prime = _key!.prime;

    if (_key is ElGamalPrivateKey) {
      /// decryption
      final gamma = input.sublist(0, inLength ~/ 2).toBigIntWithSign(1);
      final phi = input.sublist(inLength ~/ 2).toBigIntWithSign(1);

      final priv = _key as ElGamalPrivateKey;
      final m = (gamma.modPow(prime - (BigInt.one + priv.x), prime) * phi) % prime;
      output.setAll(
        outOff,
        m.toUnsignedBytes().sublist(0, output.length - outOff),
      );
    } else {
      /// encryption
      final block = (inOff != 0 || inLength != input.length) ? input.sublist(0, inLength) : input;
      final inp = block.toBigIntWithSign(1);

      if (inp > prime) {
        throw ArgumentError('Input too large for $algorithmName cipher.');
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
  reset() {}

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
