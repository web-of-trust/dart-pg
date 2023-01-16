// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'package:fixnum/fixnum.dart';
import 'package:pointycastle/api.dart';

import '../../helpers.dart';
import 'base_cipher.dart';

/// Camellia - based on RFC 3713
class CamelliaLightEngine extends BaseCipher {
  static const _blockSize = 16;

  static const _mask8 = 0xff;

  static const _sigma = [
    0xa09e667f,
    0x3bcc908b,
    0xb67ae858,
    0x4caa73b2,
    0xc6ef372f,
    0xe94f82be,
    0x54ff53a5,
    0xf1d36f1c,
    0x10e527fa,
    0xde682d1d,
    0xb05688c2,
    0xb3e6c1fd,
  ];

  /// S-box data
  static const _sbox = [
    112,
    130,
    44,
    236,
    179,
    39,
    192,
    229,
    228,
    133,
    87,
    53,
    234,
    12,
    174,
    65,
    35,
    239,
    107,
    147,
    69,
    25,
    165,
    33,
    237,
    14,
    79,
    78,
    29,
    101,
    146,
    189,
    134,
    184,
    175,
    143,
    124,
    235,
    31,
    206,
    62,
    48,
    220,
    95,
    94,
    197,
    11,
    26,
    166,
    225,
    57,
    202,
    213,
    71,
    93,
    61,
    217,
    1,
    90,
    214,
    81,
    86,
    108,
    77,
    139,
    13,
    154,
    102,
    251,
    204,
    176,
    45,
    116,
    18,
    43,
    32,
    240,
    177,
    132,
    153,
    223,
    76,
    203,
    194,
    52,
    126,
    118,
    5,
    109,
    183,
    169,
    49,
    209,
    23,
    4,
    215,
    20,
    88,
    58,
    97,
    222,
    27,
    17,
    28,
    50,
    15,
    156,
    22,
    83,
    24,
    242,
    34,
    254,
    68,
    207,
    178,
    195,
    181,
    122,
    145,
    36,
    8,
    232,
    168,
    96,
    252,
    105,
    80,
    170,
    208,
    160,
    125,
    161,
    137,
    98,
    151,
    84,
    91,
    30,
    149,
    224,
    255,
    100,
    210,
    16,
    196,
    0,
    72,
    163,
    247,
    117,
    219,
    138,
    3,
    230,
    218,
    9,
    63,
    221,
    148,
    135,
    92,
    131,
    2,
    205,
    74,
    144,
    51,
    115,
    103,
    246,
    243,
    157,
    127,
    191,
    226,
    82,
    155,
    216,
    38,
    200,
    55,
    198,
    59,
    129,
    150,
    111,
    75,
    19,
    190,
    99,
    46,
    233,
    121,
    167,
    140,
    159,
    110,
    188,
    142,
    41,
    245,
    249,
    182,
    47,
    253,
    180,
    89,
    120,
    152,
    6,
    106,
    231,
    70,
    113,
    186,
    212,
    37,
    171,
    66,
    136,
    162,
    141,
    250,
    114,
    7,
    185,
    85,
    248,
    238,
    172,
    10,
    54,
    73,
    42,
    104,
    60,
    56,
    241,
    164,
    64,
    40,
    211,
    123,
    187,
    201,
    67,
    193,
    21,
    227,
    173,
    244,
    119,
    199,
    128,
    158,
  ];

  late bool _initialised;

  late bool _keyIs128;

  final _subkey = List.filled(24 * 4, 0);

  /// for whitening
  final _kw = List.filled(4 * 2, 0);

  /// for FL and FL^(-1)
  final _ke = List.filled(6 * 2, 0);

  /// for encryption and decryption
  final _state = List.filled(4, 0);

  @override
  String get algorithmName => 'Camellia';

  @override
  int get blockSize => _blockSize;

  @override
  void init(bool forEncryption, CipherParameters? params) {
    if (params is! KeyParameter) {
      throw Exception('only simple KeyParameter expected.');
    }

    _setKey(forEncryption, params.key);
    _initialised = true;
  }

  @override
  int processBlock(Uint8List input, int inOff, Uint8List output, int outOff) {
    if (!_initialised) {
      throw Exception('Camellia is not initialized');
    }
    if ((inOff + _blockSize) > input.length) {
      throw Exception('input buffer too short');
    }
    if ((outOff + _blockSize) > output.length) {
      throw Exception('output buffer too short');
    }

    if (_keyIs128) {
      return _processBlock128(input, inOff, output, outOff);
    } else {
      return _processBlock192or256(input, inOff, output, outOff);
    }
  }

  @override
  void reset() {}

  static int _leftShift(int x, int s) {
    return (Int64(x) << s).toInt().toUnsigned(32);
  }

  static int _rightShift(int x, int s) {
    return (Int64(x) >> s).toInt().toUnsigned(32);
  }

  static int _leftRotate(int x, int s) {
    final num = Int64(x);
    return ((num << s) + (num >> (32 - s))).toInt().toUnsigned(32);
  }

  static int _rightRotate(int x, int s) {
    final num = Int64(x);
    return ((num >> s) + (num << (32 - s))).toInt().toUnsigned(32);
  }

  static void _roldq(int rot, List<int> ki, int inOff, List<int> ko, int outOff) {
    ko[0 + outOff] = _leftShift(ki[0 + inOff], rot) | _rightShift(ki[1 + inOff], 32 - rot);
    ko[1 + outOff] = _leftShift(ki[1 + inOff], rot) | _rightShift(ki[2 + inOff], 32 - rot);
    ko[2 + outOff] = _leftShift(ki[2 + inOff], rot) | _rightShift(ki[3 + inOff], 32 - rot);
    ko[3 + outOff] = _leftShift(ki[3 + inOff], rot) | _rightShift(ki[0 + inOff], 32 - rot);
    ki[0 + inOff] = ko[0 + outOff];
    ki[1 + inOff] = ko[1 + outOff];
    ki[2 + inOff] = ko[2 + outOff];
    ki[3 + inOff] = ko[3 + outOff];
  }

  static void _decroldq(int rot, List<int> ki, int inOff, List<int> ko, int outOff) {
    ko[2 + outOff] = _leftShift(ki[0 + inOff], rot) | _rightShift(ki[1 + inOff], 32 - rot);
    ko[3 + outOff] = _leftShift(ki[1 + inOff], rot) | _rightShift(ki[2 + inOff], 32 - rot);
    ko[0 + outOff] = _leftShift(ki[2 + inOff], rot) | _rightShift(ki[3 + inOff], 32 - rot);
    ko[1 + outOff] = _leftShift(ki[3 + inOff], rot) | _rightShift(ki[0 + inOff], 32 - rot);
    ki[0 + inOff] = ko[2 + outOff];
    ki[1 + inOff] = ko[3 + outOff];
    ki[2 + inOff] = ko[0 + outOff];
    ki[3 + inOff] = ko[1 + outOff];
  }

  static void _roldqo32(int rot, List<int> ki, int inOff, List<int> ko, int outOff) {
    ko[0 + outOff] = _leftShift(ki[1 + inOff], rot - 32) | _rightShift(ki[2 + inOff], 64 - rot);
    ko[1 + outOff] = _leftShift(ki[2 + inOff], rot - 32) | _rightShift(ki[3 + inOff], 64 - rot);
    ko[2 + outOff] = _leftShift(ki[3 + inOff], rot - 32) | _rightShift(ki[0 + inOff], 64 - rot);
    ko[3 + outOff] = _leftShift(ki[0 + inOff], rot - 32) | _rightShift(ki[1 + inOff], 64 - rot);
    ki[0 + inOff] = ko[0 + outOff];
    ki[1 + inOff] = ko[1 + outOff];
    ki[2 + inOff] = ko[2 + outOff];
    ki[3 + inOff] = ko[3 + outOff];
  }

  static void _decroldqo32(int rot, List<int> ki, int inOff, List<int> ko, int outOff) {
    ko[2 + outOff] = _leftShift(ki[1 + inOff], rot - 32) | _rightShift(ki[2 + inOff], 64 - rot);
    ko[3 + outOff] = _leftShift(ki[2 + inOff], rot - 32) | _rightShift(ki[3 + inOff], 64 - rot);
    ko[0 + outOff] = _leftShift(ki[3 + inOff], rot - 32) | _rightShift(ki[0 + inOff], 64 - rot);
    ko[1 + outOff] = _leftShift(ki[0 + inOff], rot - 32) | _rightShift(ki[1 + inOff], 64 - rot);
    ki[0 + inOff] = ko[2 + outOff];
    ki[1 + inOff] = ko[3 + outOff];
    ki[2 + inOff] = ko[0 + outOff];
    ki[3 + inOff] = ko[1 + outOff];
  }

  static int _bytes2uint(Uint8List src, int offset) {
    return src.sublist(offset, offset + 4).toUint32();
  }

  static void _uint2bytes(int word, Uint8List dst, int offset) {
    dst.setRange(offset, offset + 4, word.toUnsigned(32).pack32());
  }

  static int _sbox2(int x) {
    return _sbox[x].rotateLeft8(1);
  }

  static int _sbox3(int x) {
    return _sbox[x].rotateLeft8(7);
  }

  static int _sbox4(int x) {
    return _sbox[x.rotateLeft8(1)];
  }

  static void _camelliaF2(List<int> s, List<int> skey, int keyoff) {
    var t1 = s[0] ^ skey[0 + keyoff];
    var u = _sbox4((t1 & _mask8));
    u |= (_sbox3(((t1 >> 8) & _mask8)) << 8);
    u |= (_sbox2(((t1 >> 16) & _mask8)) << 16);
    u |= ((_sbox[((t1 >> 24) & _mask8)] & _mask8) << 24);

    var t2 = s[1] ^ skey[1 + keyoff];
    var v = _sbox[(t2 & _mask8)] & _mask8;
    v |= (_sbox4(((t2 >> 8) & _mask8)) << 8);
    v |= (_sbox3(((t2 >> 16) & _mask8)) << 16);
    v |= (_sbox2(((t2 >> 24) & _mask8)) << 24);

    v = _leftRotate(v, 8);
    u ^= v;
    v = _leftRotate(v, 8) ^ u;
    u = _rightRotate(u, 8) ^ v;
    s[2] ^= _leftRotate(v, 16) ^ u;
    s[3] ^= _leftRotate(u, 8);

    t1 = s[2] ^ skey[2 + keyoff];
    u = _sbox4((t1 & _mask8));
    u |= _sbox3(((t1 >> 8) & _mask8)) << 8;
    u |= _sbox2(((t1 >> 16) & _mask8)) << 16;
    u |= (_sbox[((t1 >> 24) & _mask8)] & _mask8) << 24;

    t2 = s[3] ^ skey[3 + keyoff];
    v = (_sbox[(t2 & _mask8)] & _mask8);
    v |= _sbox4(((t2 >> 8) & _mask8)) << 8;
    v |= _sbox3(((t2 >> 16) & _mask8)) << 16;
    v |= _sbox2(((t2 >> 24) & _mask8)) << 24;

    v = _leftRotate(v, 8);
    u ^= v;
    v = _leftRotate(v, 8) ^ u;
    u = _rightRotate(u, 8) ^ v;
    s[0] ^= _leftRotate(v, 16) ^ u;
    s[1] ^= _leftRotate(u, 8);
  }

  static void _camelliaFLs(List<int> s, List<int> fkey, int keyoff) {
    s[1] ^= _leftRotate(s[0] & fkey[0 + keyoff], 1);
    s[0] ^= fkey[1 + keyoff] | s[1];

    s[2] ^= fkey[3 + keyoff] | s[3];
    s[3] ^= _leftRotate(fkey[2 + keyoff] & s[2], 1);
  }

  void _setKey(bool forEncryption, Uint8List key) {
    final k = List.filled(8, 0);
    final ka = List.filled(4, 0);
    final kb = List.filled(4, 0);
    final t = List.filled(4, 0);

    switch (key.length) {
      case 16:
        _keyIs128 = true;
        k[0] = _bytes2uint(key, 0);
        k[1] = _bytes2uint(key, 4);
        k[2] = _bytes2uint(key, 8);
        k[3] = _bytes2uint(key, 12);
        break;
      case 24:
        k[0] = _bytes2uint(key, 0);
        k[1] = _bytes2uint(key, 4);
        k[2] = _bytes2uint(key, 8);
        k[3] = _bytes2uint(key, 12);
        k[4] = _bytes2uint(key, 16);
        k[5] = _bytes2uint(key, 20);
        k[6] = ~k[4];
        k[7] = ~k[5];
        _keyIs128 = false;
        break;
      case 32:
        k[0] = _bytes2uint(key, 0);
        k[1] = _bytes2uint(key, 4);
        k[2] = _bytes2uint(key, 8);
        k[3] = _bytes2uint(key, 12);
        k[4] = _bytes2uint(key, 16);
        k[5] = _bytes2uint(key, 20);
        k[6] = _bytes2uint(key, 24);
        k[7] = _bytes2uint(key, 28);
        _keyIs128 = false;
        break;
      default:
        throw Exception('key sizes are only 16/24/32 bytes.');
    }

    for (var i = 0; i < 4; i++) {
      ka[i] = k[i] ^ k[i + 4];
    }
    /* compute KA */
    _camelliaF2(ka, _sigma, 0);
    for (var i = 0; i < 4; i++) {
      ka[i] ^= k[i];
    }
    _camelliaF2(ka, _sigma, 4);

    if (_keyIs128) {
      if (forEncryption) {
        /* KL dependant keys */
        _kw[0] = k[0];
        _kw[1] = k[1];
        _kw[2] = k[2];
        _kw[3] = k[3];
        _roldq(15, k, 0, _subkey, 4);
        _roldq(30, k, 0, _subkey, 12);
        _roldq(15, k, 0, t, 0);
        _subkey[18] = t[2];
        _subkey[19] = t[3];
        _roldq(17, k, 0, _ke, 4);
        _roldq(17, k, 0, _subkey, 24);
        _roldq(17, k, 0, _subkey, 32);
        /* KA dependant keys */
        _subkey[0] = ka[0];
        _subkey[1] = ka[1];
        _subkey[2] = ka[2];
        _subkey[3] = ka[3];
        _roldq(15, ka, 0, _subkey, 8);
        _roldq(15, ka, 0, _ke, 0);
        _roldq(15, ka, 0, t, 0);
        _subkey[16] = t[0];
        _subkey[17] = t[1];
        _roldq(15, ka, 0, _subkey, 20);
        _roldqo32(34, ka, 0, _subkey, 28);
        _roldq(17, ka, 0, _kw, 4);
      } else {
        // decryption
        /* KL dependant keys */
        _kw[4] = k[0];
        _kw[5] = k[1];
        _kw[6] = k[2];
        _kw[7] = k[3];
        _decroldq(15, k, 0, _subkey, 28);
        _decroldq(30, k, 0, _subkey, 20);
        _decroldq(15, k, 0, t, 0);
        _subkey[16] = t[0];
        _subkey[17] = t[1];
        _decroldq(17, k, 0, _ke, 0);
        _decroldq(17, k, 0, _subkey, 8);
        _decroldq(17, k, 0, _subkey, 0);
        /* KA dependant keys */
        _subkey[34] = ka[0];
        _subkey[35] = ka[1];
        _subkey[32] = ka[2];
        _subkey[33] = ka[3];
        _decroldq(15, ka, 0, _subkey, 24);
        _decroldq(15, ka, 0, _ke, 4);
        _decroldq(15, ka, 0, t, 0);
        _subkey[18] = t[2];
        _subkey[19] = t[3];
        _decroldq(15, ka, 0, _subkey, 12);
        _decroldqo32(34, ka, 0, _subkey, 4);
        _roldq(17, ka, 0, _kw, 0);
      }
    } else {
      // 192bit or 256bit
      /* compute KB */
      for (var i = 0; i < 4; i++) {
        kb[i] = ka[i] ^ k[i + 4];
      }
      _camelliaF2(kb, _sigma, 8);

      if (forEncryption) {
        /* KL dependant keys */
        _kw[0] = k[0];
        _kw[1] = k[1];
        _kw[2] = k[2];
        _kw[3] = k[3];
        _roldqo32(45, k, 0, _subkey, 16);
        _roldq(15, k, 0, _ke, 4);
        _roldq(17, k, 0, _subkey, 32);
        _roldqo32(34, k, 0, _subkey, 44);
        /* KR dependant keys */
        _roldq(15, k, 4, _subkey, 4);
        _roldq(15, k, 4, _ke, 0);
        _roldq(30, k, 4, _subkey, 24);
        _roldqo32(34, k, 4, _subkey, 36);
        /* KA dependant keys */
        _roldq(15, ka, 0, _subkey, 8);
        _roldq(30, ka, 0, _subkey, 20);
        /* 32bit rotation */
        _ke[8] = ka[1];
        _ke[9] = ka[2];
        _ke[10] = ka[3];
        _ke[11] = ka[0];
        _roldqo32(49, ka, 0, _subkey, 40);

        /* KB dependant keys */
        _subkey[0] = kb[0];
        _subkey[1] = kb[1];
        _subkey[2] = kb[2];
        _subkey[3] = kb[3];
        _roldq(30, kb, 0, _subkey, 12);
        _roldq(30, kb, 0, _subkey, 28);
        _roldqo32(51, kb, 0, _kw, 4);
      } else {
        // decryption
        /* KL dependant keys */
        _kw[4] = k[0];
        _kw[5] = k[1];
        _kw[6] = k[2];
        _kw[7] = k[3];
        _decroldqo32(45, k, 0, _subkey, 28);
        _decroldq(15, k, 0, _ke, 4);
        _decroldq(17, k, 0, _subkey, 12);
        _decroldqo32(34, k, 0, _subkey, 0);
        /* KR dependant keys */
        _decroldq(15, k, 4, _subkey, 40);
        _decroldq(15, k, 4, _ke, 8);
        _decroldq(30, k, 4, _subkey, 20);
        _decroldqo32(34, k, 4, _subkey, 8);
        /* KA dependant keys */
        _decroldq(15, ka, 0, _subkey, 36);
        _decroldq(30, ka, 0, _subkey, 24);
        /* 32bit rotation */
        _ke[2] = ka[1];
        _ke[3] = ka[2];
        _ke[0] = ka[3];
        _ke[1] = ka[0];
        _decroldqo32(49, ka, 0, _subkey, 4);

        /* KB dependant keys */
        _subkey[46] = kb[0];
        _subkey[47] = kb[1];
        _subkey[44] = kb[2];
        _subkey[45] = kb[3];
        _decroldq(30, kb, 0, _subkey, 32);
        _decroldq(30, kb, 0, _subkey, 16);
        _roldqo32(51, kb, 0, _kw, 0);
      }
    }
  }

  int _processBlock128(Uint8List input, int inOff, Uint8List output, int outOff) {
    for (var i = 0; i < 4; i++) {
      _state[i] = _bytes2uint(input, inOff + (i * 4));
      _state[i] ^= _kw[i];
    }

    _camelliaF2(_state, _subkey, 0);
    _camelliaF2(_state, _subkey, 4);
    _camelliaF2(_state, _subkey, 8);
    _camelliaFLs(_state, _ke, 0);
    _camelliaF2(_state, _subkey, 12);
    _camelliaF2(_state, _subkey, 16);
    _camelliaF2(_state, _subkey, 20);
    _camelliaFLs(_state, _ke, 4);
    _camelliaF2(_state, _subkey, 24);
    _camelliaF2(_state, _subkey, 28);
    _camelliaF2(_state, _subkey, 32);

    _state[2] ^= _kw[4];
    _state[3] ^= _kw[5];
    _state[0] ^= _kw[6];
    _state[1] ^= _kw[7];

    _uint2bytes(_state[2], output, outOff);
    _uint2bytes(_state[3], output, outOff + 4);
    _uint2bytes(_state[0], output, outOff + 8);
    _uint2bytes(_state[1], output, outOff + 12);

    return _blockSize;
  }

  int _processBlock192or256(Uint8List input, int inOff, Uint8List output, int outOff) {
    for (var i = 0; i < 4; i++) {
      _state[i] = _bytes2uint(input, inOff + (i * 4));
      _state[i] ^= _kw[i];
    }

    _camelliaF2(_state, _subkey, 0);
    _camelliaF2(_state, _subkey, 4);
    _camelliaF2(_state, _subkey, 8);
    _camelliaFLs(_state, _ke, 0);
    _camelliaF2(_state, _subkey, 12);
    _camelliaF2(_state, _subkey, 16);
    _camelliaF2(_state, _subkey, 20);
    _camelliaFLs(_state, _ke, 4);
    _camelliaF2(_state, _subkey, 24);
    _camelliaF2(_state, _subkey, 28);
    _camelliaF2(_state, _subkey, 32);
    _camelliaFLs(_state, _ke, 8);
    _camelliaF2(_state, _subkey, 36);
    _camelliaF2(_state, _subkey, 40);
    _camelliaF2(_state, _subkey, 44);

    _state[2] ^= _kw[4];
    _state[3] ^= _kw[5];
    _state[0] ^= _kw[6];
    _state[1] ^= _kw[7];

    _uint2bytes(_state[2], output, outOff);
    _uint2bytes(_state[3], output, outOff + 4);
    _uint2bytes(_state[0], output, outOff + 8);
    _uint2bytes(_state[1], output, outOff + 12);
    return _blockSize;
  }
}
