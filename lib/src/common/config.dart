/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import '../enum/aead_algorithm.dart';
import '../enum/compression_algorithm.dart';
import '../enum/hash_algorithm.dart';
import '../enum/preset_rfc.dart';
import '../enum/symmetric_algorithm.dart';

/// Configuration class
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
final class Config {
  static const aeadSupported = true;
  static const aeadChunkSizeMin = 10;
  static const aeadChunkSizeMax = 16;

  static int aeadChunkSize = 12;

  static bool allowUnauthenticated = false;

  static bool checksumRequired = false;

  static bool aeadProtect = false;

  static PresetRfc presetRfc = PresetRfc.rfc4880;

  static HashAlgorithm preferredHash = HashAlgorithm.sha256;

  static SymmetricAlgorithm preferredSymmetric = SymmetricAlgorithm.aes256;

  static CompressionAlgorithm preferredCompression =
      CompressionAlgorithm.uncompressed;

  static AeadAlgorithm preferredAead = AeadAlgorithm.ocb;
}
