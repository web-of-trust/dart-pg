/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'package:pointycastle/asn1.dart';

import 'hash_algorithm.dart';
import 'symmetric_algorithm.dart';

/// Elliptic curve cryptography enum
/// See https://www.rfc-editor.org/rfc/rfc9580#section-9.2
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum Ecc {
  prime256v1([1, 2, 840, 10045, 3, 1, 7], '1.2.840.10045.3.1.7'),
  secp256k1([1, 3, 132, 0, 10], '1.3.132.0.10'),
  secp384r1([1, 3, 132, 0, 34], '1.3.132.0.34'),
  secp521r1([1, 3, 132, 0, 35], '1.3.132.0.35'),
  brainpoolP256r1([1, 3, 36, 3, 3, 2, 8, 1, 1, 7], '1.3.36.3.3.2.8.1.1.7'),
  brainpoolP384r1([1, 3, 36, 3, 3, 2, 8, 1, 1, 11], '1.3.36.3.3.2.8.1.1.11'),
  brainpoolP512r1([1, 3, 36, 3, 3, 2, 8, 1, 1, 13], '1.3.36.3.3.2.8.1.1.13'),
  ed25519([1, 3, 6, 1, 4, 1, 11591, 15, 1], '11.3.6.1.4.1.3029.1.5.1'),
  curve25519([1, 3, 6, 1, 4, 1, 3029, 1, 5, 1], '1.3.6.1.4.1.3029.1.5.1');

  final List<int> identifier;

  final String identifierString;

  const Ecc(this.identifier, this.identifierString);

  ASN1ObjectIdentifier get asn1Oid => ASN1ObjectIdentifier(identifier);

  HashAlgorithm get hashAlgorithm => switch (this) {
        brainpoolP256r1 || curve25519 || prime256v1 || secp256k1 => HashAlgorithm.sha256,
        brainpoolP384r1 || secp384r1 => HashAlgorithm.sha384,
        brainpoolP512r1 || ed25519 || secp521r1 => HashAlgorithm.sha512,
      };

  SymmetricAlgorithm get symmetricAlgorithm => switch (this) {
        brainpoolP256r1 || curve25519 || ed25519 || prime256v1 || secp256k1 => SymmetricAlgorithm.aes128,
        brainpoolP384r1 || secp384r1 => SymmetricAlgorithm.aes192,
        brainpoolP512r1 || secp521r1 => SymmetricAlgorithm.aes256,
      };
}
