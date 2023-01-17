import 'dart:typed_data';

import 'package:dart_pg/src/crypto/asymmetric/elgamal.dart';
import 'package:dart_pg/src/helpers.dart';
import 'package:test/test.dart';

void main() {
  group('ElGamal engine tests', () {
    test('Enc 512 Test', () {
      final p512 = BigInt.parse(
          '9494fec095f3b85ee286542b3836fc81a5dd0a0349b4c239dd38744d488cf8e31db8bcb7d33b41abb9e5a33cca9144b1cef332c94bf0573bf047a3aca98cdf3b',
          radix: 16);
      final g512 = BigInt.parse(
          '153d5d6172adb43045b68ae8e1de1070b6137005686d29d3d73a7749199681ee5b212c9b96bfdcfa5b20cd5e3fd2044895d609cf9b410b7a0f12ca1cb9a428cc',
          radix: 16);

      _elGamalEncryptionTest(p512, g512, 512);
    });

    test('Enc 768 Test', (() {
      final p768 = BigInt.parse(
          '8c9dd223debed1b80103b8b309715be009d48860ed5ae9b9d5d8159508efd802e3ad4501a7f7e1cfec78844489148cd72da24b21eddd01aa624291c48393e277cfc529e37075eccef957f3616f962d15b44aeab4039d01b817fde9eaa12fd73f',
          radix: 16);
      final g768 = BigInt.parse(
          '7c240073c1316c621df461b71ebb0cdcc90a6e5527e5e126633d131f87461c4dc4afc60c2cb0f053b6758871489a69613e2a8b4c8acde23954c08c81cbd36132cfd64d69e4ed9f8e51ed6e516297206672d5c0a69135df0a5dcf010d289a9ca1',
          radix: 16);

      _elGamalEncryptionTest(p768, g768, 768);
    }));

    test('Enc 1024 Test', (() {
      final p1024 = BigInt.parse(
          'a00e283b3c624e5b2b4d9fbc2653b5185d99499b00fd1bf244c6f0bb817b4d1c451b2958d62a0f8a38caef059fb5ecd25d75ed9af403f5b5bdab97a642902f824e3c13789fed95fa106ddfe0ff4a707c85e2eb77d49e68f2808bcea18ce128b178cd287c6bc00efa9a1ad2a673fe0dceace53166f75b81d6709d5f8af7c66bb7',
          radix: 16);
      final g1024 = BigInt.parse(
          '1db17639cdf96bc4eabba19454f0b7e5bd4e14862889a725c96eb61048dcd676ceb303d586e30f060dbafd8a571a39c4d823982117da5cc4e0f89c77388b7a08896362429b94a18a327604eb7ff227bffbc83459ade299e57b5f77b50fb045250934938efa145511166e3197373e1b5b1e52de713eb49792bedde722c6717abf',
          radix: 16);

      _elGamalEncryptionTest(p1024, g1024, 1024);
    }));
  });
}

void _elGamalEncryptionTest(BigInt p, BigInt g, int size) {
  final x = _dhCalculatePrivateKey(p);
  final privateKey = ElGamalPrivateKey(x, p, g);
  final publicKey = privateKey.publicKey;

  final engine = ElGamalEngine();
  engine.init(true, ElGamalKeyParameters(publicKey));
  expect(engine.outputBlockSize, size ~/ 4, reason: "$size outputBlockSize on encryption failed.");

  final message = "5468697320697320612074657374".hexToBytes();
  final plainText = message;
  final cipherText = Uint8List(engine.outputBlockSize);
  engine.processBlock(plainText, 0, plainText.length, cipherText, 0);

  engine.init(false, ElGamalKeyParameters(privateKey));
  engine.processBlock(cipherText, 0, cipherText.length, plainText, 0);

  expect(engine.outputBlockSize, (size ~/ 8) - 1, reason: "$size outputBlockSize on decryption failed.");
  expect(message, equals(plainText), reason: '$size bit test failed');

  print(plainText.toHexadecimal());
}

BigInt _dhCalculatePrivateKey(BigInt p) {
  final random = newSecureRandom();
  final min = BigInt.two;
  final max = p - BigInt.two;
  final minWeight = max.bitLength >> 2;
  var x = random.nextBigInteger(max.bitLength);
  while ((x.compareTo(min) < 0) || (x.compareTo(max) > 0) || (_getNafWeight(x) < minWeight)) {
    x = random.nextBigInteger(max.bitLength);
  }
  return x;
}

int _getNafWeight(BigInt k) {
  if (k.sign == 0) {
    return 0;
  }
  final k3 = (k << 1) + k;
  final diff = k3 ^ k;
  return diff.bitLength;
}
