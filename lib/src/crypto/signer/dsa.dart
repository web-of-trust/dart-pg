// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/api.dart';

import '../../helpers.dart';

class DSASigner implements Signer {
  final Digest? _digest;

  late DSAAsymmetricKey? _key;

  late SecureRandom _random;

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
      _random = newSecureRandom();
    }
    if (params is DSAKeyParameters) {
      _key = params.getKey;

      if (_forSigning) {
        if (_key is! DSAPrivateKey) {
          throw ArgumentError('Signing requires private key.');
        }
      } else {
        if (_key is! DSAPublicKey) {
          throw ArgumentError('Verification requires public key.');
        }
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

    final pri = _key as DSAPrivateKey;
    final q = pri.q;
    final e = _calculateE(q, _hashMessageIfNeeded(message));

    BigInt r;
    BigInt s;

    do {
      // generate s
      var k = BigInt.zero;
      var kInv = BigInt.zero;
      do {
        // generate r
        try {
          k = _calculateK(q);
          kInv = k.modInverse(q);
          // r = (g**k mod p) mod q
          r = pri.g.modPow(k, pri.p) % q;
        } catch (_) {
          r = BigInt.zero;
        }
      } while (r.sign == 0);
      // s = k^-1 * (E(m) + x*r) mod q
      s = kInv * (e + (pri.x * r)) % q;
    } while (s.sign == 0);

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

    final e = _calculateE(q, _hashMessageIfNeeded(message));
    // w = s^-1 mod q
    final w = signature.s.modInverse(q);

    // u1 = E(m) * w mod q
    final u1 = (e * w) % q;
    // u2 = r * w mod q
    final u2 = (signature.r * w) % q;

    // t1 = g**u1 mod p
    final t1 = pub.g.modPow(u1, pub.p);
    // t2 = y**u2 mod p
    final t2 = pub.y.modPow(u2, pub.p);

    // v = (g**1 * y**u2 mod p) mod q
    final v = ((t1 * t2) % pub.p) % q;

    return v.compareTo(signature.r) == 0;
  }

  BigInt _calculateE(BigInt n, Uint8List message) {
    final length = min(message.length, n.bitLength ~/ 8);
    return message.sublist(0, length).toBigIntWithSign(1);
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
  /// g ** x mod p
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
