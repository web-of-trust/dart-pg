// Copyright 2022-present by Nguyen Van Nguyen <nguyennv1981@gmail.com>. All rights reserved.
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

import 'dart:typed_data';

import 'user_attribute_subpacket.dart';

class ImageAttribute extends UserAttributeSubpacket {
  static const jpeg = 1;

  static final Uint8List _zeroes = Uint8List(12);

  ImageAttribute(final Uint8List data, {super.longLength}) : super(1, data);

  factory ImageAttribute.fromImageData(final Uint8List imageData, {final int imageType = jpeg}) {
    final List<int> data = [0x10, 0x00, 0x01, imageType & 0xff];
    data.addAll(_zeroes);
    data.addAll(imageData);
    return ImageAttribute(Uint8List.fromList(data));
  }

  int get hdrLength => (data[1] << 8) | data[0];

  int get version => data[2];

  int get encoding => data[3];

  Uint8List get imageData => data.sublist(hdrLength);
}
