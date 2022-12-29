// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum S2kType {
  simple(0),
  salted(1),
  iterated(3),
  gnu(101);

  final int value;

  const S2kType(this.value);
}
