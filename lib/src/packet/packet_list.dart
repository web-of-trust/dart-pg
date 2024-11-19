/// Copyright 2024-present by Dart Privacy Guard project. All rights reserved.
/// For the full copyright and license information, please view the LICENSE
/// file that was distributed with this source code.

library;

import 'dart:collection';
import 'dart:typed_data';

import 'package:dart_pg/src/enum/packet_type.dart';

import '../type/packet.dart';
import '../type/packet_list.dart';

/// This class represents a list of OpenPGP packets.
/// Author Nguyen Van Nguyen <nguyennv1981@gmail.com>
class PacketList extends ListBase<PacketInterface> implements PacketListInterface {
  @override
  final List<PacketInterface> packets;

  PacketList(final Iterable<PacketInterface> packets)
      : packets = packets.toList(
          growable: false,
        );

  /// Decode packets from bytes
  factory PacketList.decode(Uint8List bytes) {
    final packets = <PacketInterface>[];
    return PacketList(packets);
  }

  @override
  Uint8List encode() => Uint8List.fromList(
        packets.map((packet) => packet.encode()).expand((byte) => byte).toList(growable: false),
      );

  PacketList filterByTypes([final List<PacketType> tags = const []]) {
    if (tags.isNotEmpty) {
      return PacketList(packets.where((packet) => tags.contains(packet.type)));
    }
    return this;
  }

  List<int> indexOfTypes([final List<PacketType> tags = const []]) {
    final indexes = <int>[];
    for (var i = 0; i < packets.length; i++) {
      final packet = packets[i];
      if (tags.contains(packet.type)) {
        indexes.add(i);
      }
    }

    return indexes;
  }

  @override
  int get length => packets.length;

  @override
  PacketInterface operator [](int index) => packets[index];

  @override
  void operator []=(int index, PacketInterface packet) {
    packets[index] = packet;
  }

  @override
  set length(int newLength) {
    packets.length = newLength;
  }
}
