// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

class PGPMimeBuilder {
  static const signedPreamble = 'This is an OpenPGP/MIME signed message (RFC 4880 and 3156)';

  static const encryptedPreamble = 'This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)';

  static const signedDescription = 'OpenPGP digital signature';

  static const encryptedDescription = 'OpenPGP encrypted message';

  static const versionDescription = 'OpenPGP/MIME Versions Identification';
}
