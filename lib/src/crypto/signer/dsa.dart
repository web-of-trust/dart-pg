// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../helpers.dart';

class DSASigner implements Signer {
  final Digest? _digest;

  late final DSAAsymmetricKey? _key;

  late final SecureRandom _random;

  bool _forSigning = false;

  DSASigner([this._digest]);

  @override
  String get algorithmName => '${_digest?.algorithmName}/DSA';

  @override
  void init(bool forSigning, CipherParameters params) {
    _forSigning = forSigning;
    if (params is ParametersWithRandom) {
      _random = params.random;
      params = params.parameters;
    } else {
      final random = Random.secure();
      final max = double.maxFinite.toInt();
      _random = SecureRandom('Fortuna')
        ..seed(KeyParameter(Uint8List.fromList(List.generate(32, ((_) => random.nextInt(max))))));
    }
    if (params is DSAKeyParameters) {
      _key = params.getKey;

      if (_forSigning && _key is! DSAPrivateKey) {
        throw ArgumentError('Signing Requires Private Key.');
      } else if (_key is! DSAPublicKey) {
        throw ArgumentError('Verification Requires Public Key.');
      }
    } else {
      throw ArgumentError('DSAKeyParameters are required.');
    }
  }

  @override
  void reset() {
    _digest?.reset();
  }

  @override
  DSASignature generateSignature(Uint8List message) {
    if (!_forSigning) {
      throw StateError('DSASigner not initialised for signature generation');
    }
    message = _hashMessageIfNeeded(message);

    final pri = _key as DSAPrivateKey;
    final q = pri.q;
    final e = _calculateE(q, message);
    final k = _calculateK(q) + _getRandomizer(q);

    final r = pri.g.modPow(k, pri.p) % q;
    final s = (k.modInverse(q) * (e + (pri.x * r))) % q;

    return DSASignature(r, s);
  }

  @override
  bool verifySignature(Uint8List message, covariant DSASignature signature) {
    final pub = _key as DSAPublicKey;
    final q = pub.q;

    if (signature.r.compareTo(BigInt.one) < 0 || signature.r.compareTo(q) >= 0) {
      return false;
    }
    if (signature.s.compareTo(BigInt.one) < 0 || signature.s.compareTo(q) >= 0) {
      return false;
    }

    message = _hashMessageIfNeeded(message);

    final e = _calculateE(q, message);
    final c = signature.s.modInverse(q);

    var u1 = (e * c) % q;
    var u2 = (signature.r * c) % q;
    u1 = pub.g.modPow(u1, pub.p);
    u2 = pub.y.modPow(u2, pub.p);

    final v = ((u1 * u2) % pub.p) % q;

    return v == signature.r;
  }

  BigInt _calculateE(BigInt n, Uint8List message) {
    final log2n = n.bitLength;
    final messageBitLength = message.length * 8;
    if (log2n >= messageBitLength) {
      return message.toBigIntWithSign(1);
    } else {
      return message.toBigIntWithSign(1) >> (messageBitLength - log2n);
    }
  }

  BigInt _getRandomizer(BigInt q) {
    return (_random.nextBigInteger(7) + BigInt.from(128)) * q;
  }

  BigInt _calculateK(BigInt n) {
    BigInt k;
    do {
      k = _random.nextBigInteger(n.bitLength);
    } while (k == BigInt.zero || k >= n);
    return k;
  }

  Uint8List _hashMessageIfNeeded(Uint8List message) {
    if (_digest != null) {
      _digest!.reset();
      return _digest!.process(message);
    } else {
      return message;
    }
  }
}

class DSASignature implements Signature {
  final BigInt r;
  final BigInt s;

  DSASignature(this.r, this.s);
}

abstract class DSAAsymmetricKey implements AsymmetricKey {
  /// prime
  final BigInt p;

  /// group order
  final BigInt q;

  /// group generator
  final BigInt g;

  DSAAsymmetricKey(this.p, this.q, this.g);
}

class DSAPublicKey extends DSAAsymmetricKey implements PublicKey {
  /// g^x mod p
  final BigInt y;

  DSAPublicKey(this.y, super.p, super.q, super.g);
}

class DSAPrivateKey extends DSAAsymmetricKey implements PrivateKey {
  /// secret exponent
  final BigInt x;

  /// public key
  final DSAPublicKey publicKey;

  DSAPrivateKey(this.x, super.p, super.q, super.g) : publicKey = DSAPublicKey(g.modPow(x, p), p, q, g);

  BigInt get y => publicKey.y;
}

class DSAKeyParameters extends AsymmetricKeyParameter {
  DSAKeyParameters(DSAAsymmetricKey key) : super(key);

  DSAAsymmetricKey get getKey => key as DSAAsymmetricKey;
}