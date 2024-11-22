/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

/// Compression algorithms enum
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
enum CompressionAlgorithm {
  uncompressed(0),
  zip(1),
  zlib(2),
  bzip2(3);

  final int value;

  const CompressionAlgorithm(this.value);
}
