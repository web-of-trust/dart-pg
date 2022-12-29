// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

enum SignatureType {
  binary(0),
  text(1),
  standalone(2),
  certGeneric(16),
  certPersona(17),
  certCasual(18),
  certPositive(19),
  certRevocation(48),
  subkeyBinding(24),
  keyBinding(25),
  key(31),
  keyRevocation(32),
  subkeyRevocation(40),
  timestamp(64),
  thirdParty(80);

  final int value;

  const SignatureType(this.value);
}
