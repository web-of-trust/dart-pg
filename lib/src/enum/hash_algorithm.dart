// Copyright 2022-present by Dart Privacy Guard project. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

/// Hash Algorithms
/// See https://www.rfc-editor.org/rfc/rfc4880#section-9.4
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum HashAlgorithm {
  md5(1),
  sha1(2),
  ripemd160(3),
  sha256(8),
  sha384(9),
  sha512(10),
  sha224(11);

  final int value;

  const HashAlgorithm(this.value);

  /// pointy castle digest name
  String get digestName {
    switch (this) {
      case md5:
        return 'MD5';
      case sha1:
        return 'SHA-1';
      case ripemd160:
        return 'RIPEMD-160';
      case sha256:
        return 'SHA-256';
      case sha384:
        return 'SHA-384';
      case sha512:
        return 'SHA-512';
      case sha224:
        return 'SHA-224';
    }
  }

  int get digestSize {
    switch (this) {
      case md5:
        return 16;
      case sha1:
        return 20;
      case ripemd160:
        return 20;
      case sha256:
        return 32;
      case sha384:
        return 48;
      case sha512:
        return 64;
      case sha224:
        return 28;
    }
  }

  int get saltSize {
    switch (this) {
      case md5:
      case sha1:
      case ripemd160:
        return 8;
      case sha224:
      case sha256:
        return 16;
      case sha384:
        return 24;
      case sha512:
        return 32;
    }
  }
}
