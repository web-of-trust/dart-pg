// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../helpers.dart';

class ElGamalEngine implements AsymmetricBlockCipher {
  late final ElGamalAsymmetricKey? _key;
  late final SecureRandom _random;

  bool _forEncryption = false;

  late final int _bitSize;

  @override
  String get algorithmName => 'ElGamal';

  @override
  void init(bool forEncryption, CipherParameters params) {
    _forEncryption = forEncryption;
    if (params is ParametersWithRandom) {
      _random = params.random;
      params = params.parameters;
    } else {
      final random = Random.secure();
      final max = double.maxFinite.toInt();
      _random = SecureRandom('Fortuna')
        ..seed(KeyParameter(Uint8List.fromList(List.generate(32, ((_) => random.nextInt(max))))));
    }
    if (params is ElGamalKeyParameters) {
      _bitSize = params.getKey.p.bitLength;
      _key = params.getKey;

      if (_forEncryption && _key is! ElGamalPublicKey) {
        throw ArgumentError('ElGamalPublicKey are required for encryption.');
      } else if (_key is! ElGamalPrivateKey) {
        throw ArgumentError('ElGamalPublicKey are required for decryption.');
      }
    } else {
      throw ArgumentError('ElGamalKeyParameters are required.');
    }
  }

  @override
  int get inputBlockSize => _forEncryption ? (_bitSize - 1) ~/ 8 : 2 * ((_bitSize + 7) ~/ 8);

  @override
  int get outputBlockSize => _forEncryption ? 2 * ((_bitSize + 7) ~/ 8) : (_bitSize - 1) ~/ 8;

  @override
  Uint8List process(Uint8List data) {
    var out = Uint8List(outputBlockSize);
    var len = processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

  @override
  int processBlock(Uint8List input, int inOff, int inLen, Uint8List output, int outOff) {
    if (_key == null) {
      throw StateError('$algorithmName not initialised');
    }

    int maxLength = _forEncryption ? (_bitSize - 1 + 7) ~/ 8 : inputBlockSize;
    if (inLen > maxLength) {
      throw ArgumentError('input too large for $algorithmName cipher.');
    }
    final p = _key!.p;

    if (_key is ElGamalPrivateKey) {
      /// decryption
      final in1 = Uint8List.fromList(input.sublist(0, inLen ~/ 2));
      final in2 = Uint8List.fromList(input.sublist(inLen ~/ 2));

      final gamma = in1.toBigInt();
      final phi = in2.toBigInt();

      final priv = _key as ElGamalPrivateKey;
      final m = (gamma.modPow(p - (BigInt.one + priv.x), p) * phi) % p;
      output.setAll(outOff, m.toBytes());
    } else {
      /// encryption
      final block = (inOff != 0 || inLen != input.length) ? input.sublist(0, inLen) : input;
      final inp = block.toBigInt();

      if (inp > p) {
        throw ArgumentError('input too large for $algorithmName cipher.');
      }

      var k = _random.nextBigInteger(p.bitLength);
      while (k == BigInt.zero || k.compareTo(p - BigInt.two) > 0) {
        k = _random.nextBigInteger(p.bitLength);
      }

      final pub = _key as ElGamalPublicKey;
      final g = _key!.g;
      final gamma = g.modPow(k, p);
      final phi = (inp * (pub.y.modPow(k, p))) % p;

      output.setAll(outOff, [
        ...gamma.toBytes().sublist(0, outputBlockSize ~/ 2),
        ...phi.toBytes().sublist(0, outputBlockSize ~/ 2),
      ]);
    }

    return output.length;
  }

  @override
  void reset() {}
}

abstract class ElGamalAsymmetricKey implements AsymmetricKey {
  /// prime
  final BigInt p;

  /// group generator
  final BigInt g;

  ElGamalAsymmetricKey(this.p, this.g);
}

class ElGamalPublicKey extends ElGamalAsymmetricKey implements PublicKey {
  /// g^x mod p
  final BigInt y;

  ElGamalPublicKey(this.y, super.p, super.g);
}

class ElGamalPrivateKey extends ElGamalAsymmetricKey implements PrivateKey {
  /// secret exponent
  final BigInt x;

  /// public key
  final ElGamalPublicKey publicKey;

  ElGamalPrivateKey(this.x, super.p, super.g) : publicKey = ElGamalPublicKey(g.modPow(x, p), p, g);

  BigInt get y => publicKey.y;
}

class ElGamalKeyParameters extends AsymmetricKeyParameter {
  ElGamalKeyParameters(ElGamalAsymmetricKey key) : super(key);

  ElGamalAsymmetricKey get getKey => key as ElGamalAsymmetricKey;
}
