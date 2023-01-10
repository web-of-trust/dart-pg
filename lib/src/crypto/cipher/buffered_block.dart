// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:pointycastle/api.dart';

class BufferedBlock {
  final BlockCipher _underlyingCipher;

  late final Uint8List _buffer;

  int _bufOff = 0;

  BufferedBlock(this._underlyingCipher) {
    _buffer = Uint8List(_underlyingCipher.blockSize);
  }

  BlockCipher get underlyingCipher => _underlyingCipher;

  /// return the size of the output buffer required for an update
  /// an input of len bytes.
  int getUpdateOutputSize(int length) {
    final total = length + _bufOff;
    final leftOver = total % _buffer.length;
    return total - leftOver;
  }

  /// return the size of the output buffer required for an update plus a
  /// doFinal with an input of 'length' bytes.
  int getOutputSize(int length) {
    return length + _bufOff;
  }

  /// initialise the cipher.
  void init(final bool forEncryption, final CipherParameters? params) {
    reset();
    _underlyingCipher.init(forEncryption, params);
  }

  /// process a single byte, producing an output block if necessary.
  int processByte(int input, Uint8List output, int outOff) {
    _buffer[_bufOff++] = input & 0xff;
    if (_bufOff == _buffer.length) {
      if ((outOff + _buffer.length) > output.length) {
        throw ArgumentError('output buffer too short');
      }

      _bufOff = 0;
      return _underlyingCipher.processBlock(_buffer, 0, output, outOff);
    }
    return 0;
  }

  /// process a single byte, producing an output block if necessary.
  Uint8List processInputByte(int input) {
    final outLength = getUpdateOutputSize(1);
    final outBytes = Uint8List(outLength);

    final pos = processByte(input, outBytes, 0);

    if (outLength > 0 && pos < outLength) {
      return outBytes.sublist(0, pos);
    }

    return outBytes;
  }

  /// process an array of bytes, producing output if necessary.
  int processBytes(Uint8List input, int inOff, int length, Uint8List output, int outOff) {
    if (length < 1) {
      if (length < 0) {
        throw ArgumentError("Can't have a negative input length!");
      }
      return 0;
    }

    final blockSize = _underlyingCipher.blockSize;
    final outLength = getUpdateOutputSize(length);
    if (outLength > 0 && ((outOff + outLength) > output.length)) {
      throw ArgumentError('output buffer too short');
    }

    var resultLen = 0;
    final gapLen = _buffer.lengthInBytes - _bufOff;
    if (length > gapLen) {
      _buffer.setRange(_bufOff, _bufOff + gapLen, Uint8List.view(input.buffer, inOff, gapLen));
      resultLen += _underlyingCipher.processBlock(_buffer, 0, output, outOff);

      _bufOff = 0;
      length -= gapLen;
      inOff += gapLen;

      while (length > _buffer.lengthInBytes) {
        resultLen += _underlyingCipher.processBlock(input, inOff, output, outOff + resultLen);

        length -= blockSize;
        inOff += blockSize;
      }
    }

    _buffer.setRange(_bufOff, _bufOff + length, Uint8List.view(input.buffer, inOff, length));
    _bufOff += length;

    if (_bufOff == _buffer.lengthInBytes) {
      resultLen += _underlyingCipher.processBlock(_buffer, 0, output, outOff + resultLen);
      _bufOff = 0;
    }

    return resultLen;
  }

  Uint8List processInputBytes(Uint8List input, int inOff, int length) {
    if (length < 1) {
      return Uint8List(0);
    }

    final outLength = getUpdateOutputSize(length);
    final outBytes = Uint8List(outLength);

    final pos = processBytes(input, inOff, length, outBytes, 0);
    if (outLength > 0 && pos < outLength) {
      return outBytes.sublist(0, pos);
    }

    return outBytes;
  }

  /// Process the last block in the buffer.
  int doFinal(Uint8List output, int outOff) {
    if (outOff + _bufOff > output.length) {
      throw ArgumentError('output buffer too short for doFinal()');
    }

    var resultLen = 0;
    if (_bufOff != 0) {
      _underlyingCipher.processBlock(_buffer, 0, _buffer, 0);
      resultLen = _bufOff;
      _bufOff = 0;
      output.setAll(outOff, _buffer.sublist(0, resultLen));
    }

    reset();
    return resultLen;
  }

  /// Reset the buffer and cipher. After resetting the object is in the same
  /// state as it was after the last init (if there was one).
  void reset() {
    _buffer.fillRange(0, _buffer.length, 0);

    _bufOff = 0;
    _underlyingCipher.reset();
  }
}
