// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'key_params.dart';

class KeyPairParams<P extends KeyParams, S extends KeyParams> {
  final P publicParams;
  final S secretParams;

  KeyPairParams(this.publicParams, this.secretParams);

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is KeyPairParams &&
          runtimeType == other.runtimeType &&
          publicParams == other.publicParams &&
          secretParams == other.secretParams;

  @override
  int get hashCode => publicParams.hashCode ^ secretParams.hashCode;
}
