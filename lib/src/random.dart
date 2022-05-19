library src;

import 'dart:math';
import 'dart:typed_data';

class AgeRandom {
  const AgeRandom();

  Uint8List bytes(int length) {
    final random = Random.secure();
    final data = Uint8List(length);
    for (int i = 0; i < length; i++) {
      data[i] = random.nextInt(256);
    }
    return data;
  }
}