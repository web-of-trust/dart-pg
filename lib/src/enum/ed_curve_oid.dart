// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum EdCurveOid {
  ed25519('1.3.6.1.4.1.11591.15.1'),
  curve25519('1.3.6.1.4.1.3029.1.5.1');

  final String identifierString;

  const EdCurveOid(this.identifierString);

  List<int> get identifier {
    switch (this) {
      case ed25519:
        return [1, 3, 6, 1, 4, 1, 11591, 15, 1];
      case curve25519:
        return [1, 3, 6, 1, 4, 1, 3029, 1, 5, 1];
    }
  }
}
