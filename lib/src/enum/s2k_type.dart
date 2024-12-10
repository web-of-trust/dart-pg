/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// String to key specifier types enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum S2kType {
  simple(0),
  salted(1),
  iterated(3),
  argon2(4),
  gnu(101);

  final int value;

  const S2kType(this.value);

  int get length => switch (this) {
        simple => 2,
        salted => 10,
        iterated => 11,
        argon2 => 20,
        gnu => 6,
      };
}
