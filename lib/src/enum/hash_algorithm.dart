/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Hash Algorithms enum
/// See https://www.rfc-editor.org/rfc/rfc9580#section-9.5
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum HashAlgorithm {
  md5(1),
  sha1(2),
  ripemd160(3),
  sha256(8),
  sha384(9),
  sha512(10),
  sha224(11),
  sha3_256(12),
  sha3_512(14);

  final int value;

  const HashAlgorithm(this.value);

  /// pointy castle digest name
  String get digestName => switch (this) {
        md5 => 'MD5',
        sha1 => 'SHA-1',
        ripemd160 => 'RIPEMD-160',
        sha256 => 'SHA-256',
        sha384 => 'SHA-384',
        sha512 => 'SHA-512',
        sha224 => 'SHA-224',
        sha3_256 => 'SHA3-256',
        sha3_512 => 'SHA3-512',
      };

  int get digestSize => switch (this) {
        md5 => 16,
        sha1 => 20,
        ripemd160 => 20,
        sha256 || sha3_256 => 32,
        sha384 => 48,
        sha512 || sha3_512 => 64,
        sha224 => 28,
      };

  int get saltSize => switch (this) {
        md5 || sha1 || ripemd160 => 0,
        sha224 || sha256 || sha3_256 => 16,
        sha384 => 24,
        sha512 || sha3_512 => 32,
      };
}
