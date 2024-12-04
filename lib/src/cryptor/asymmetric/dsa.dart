/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/api.dart';

import '../../common/helpers.dart';

/// Implementation of DSA (digital signature algorithm)
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class DSASigner implements Signer {
  final Digest? _digest;

  late DSAAsymmetricKey? _key;

  late SecureRandom _random;

  bool _forSigning = false;

  DSASigner([this._digest]);

  @override
  get algorithmName => '${_digest?.algorithmName}/DSA';

  @override
  init(final bool forSigning, CipherParameters params) {
    _forSigning = forSigning;
    if (params is ParametersWithRandom) {
      _random = params.random;
      params = params.parameters;
    } else {
      _random = Helper.secureRandom;
    }
    if (params is AsymmetricKeyParameter<DSAAsymmetricKey>) {
      _key = params.key;

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
      throw ArgumentError('AsymmetricKeyParameter are required.');
    }
  }

  @override
  reset() {
    _digest?.reset();
  }

  @override
  DSASignature generateSignature(final Uint8List message) {
    if (!_forSigning) {
      throw StateError('DSA signer not initialised for signature generation');
    }

    final pri = _key as DSAPrivateKey;
    final q = pri.order;
    final e = _calculateE(q, _hashMessageIfNeeded(message));

    BigInt r, s;

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
          r = pri.generator.modPow(k, pri.prime) % q;
        } catch (_) {
          r = BigInt.zero;
        }
      } while (r.sign == 0);
      // s = k^-1 * (E(m) + x*r) mod q
      s = (kInv * (e + (pri.x * r))) % q;
    } while (s.sign == 0);

    return DSASignature(r, s);
  }

  @override
  verifySignature(
    final Uint8List message,
    covariant final DSASignature signature,
  ) {
    final pub = _key as DSAPublicKey;
    final q = pub.order;

    if (signature.r.sign < 0 || signature.r.compareTo(q) >= 0) {
      return false;
    }
    if (signature.s.sign < 0 || signature.s.compareTo(q) >= 0) {
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
    final t1 = pub.generator.modPow(u1, pub.prime);
    // t2 = y**u2 mod p
    final t2 = pub.y.modPow(u2, pub.prime);

    // v = (g**1 * y**u2 mod p) mod q
    final v = ((t1 * t2) % pub.prime) % q;

    return v.compareTo(signature.r) == 0;
  }

  BigInt _calculateE(final BigInt n, final Uint8List message) {
    final length = min(message.length, n.bitLength ~/ 8);
    return message.sublist(0, length).toBigIntWithSign(1);
  }

  BigInt _calculateK(final BigInt n) {
    BigInt k;
    do {
      k = _random.nextBigInteger(n.bitLength);
    } while (k.sign == 0 || k >= n);
    return k;
  }

  Uint8List _hashMessageIfNeeded(Uint8List message) {
    if (_digest != null) {
      _digest.reset();
      return _digest.process(message);
    } else {
      return message;
    }
  }
}

class DSASignature implements Signature {
  final BigInt r;
  final BigInt s;

  DSASignature(this.r, this.s);

  Uint8List encode() => Uint8List.fromList([
        ...r.bitLength.pack16(),
        ...r.toUnsignedBytes(),
        ...s.bitLength.pack16(),
        ...s.toUnsignedBytes(),
      ]);

  @override
  String toString() => '(${r.toString()},${s.toString()})';

  @override
  operator ==(other) {
    if (other is! DSASignature) return false;
    return (other.r == r) && (other.s == s);
  }

  @override
  get hashCode {
    return r.hashCode + s.hashCode;
  }
}

abstract class DSAAsymmetricKey implements AsymmetricKey {
  /// prime p
  final BigInt prime;

  /// group order q
  final BigInt order;

  /// group generator g
  final BigInt generator;

  DSAAsymmetricKey(this.prime, this.order, this.generator);
}

class DSAPublicKey extends DSAAsymmetricKey implements PublicKey {
  /// public exponent y = g ** x mod p
  final BigInt y;

  DSAPublicKey(this.y, super.prime, super.order, super.generator);
}

class DSAPrivateKey extends DSAAsymmetricKey implements PrivateKey {
  /// secret exponent
  final BigInt x;

  /// public key
  final DSAPublicKey publicKey;

  DSAPrivateKey(this.x, super.prime, super.order, super.generator)
      : publicKey = DSAPublicKey(
          generator.modPow(x, prime),
          prime,
          order,
          generator,
        );

  BigInt get y => publicKey.y;
}
