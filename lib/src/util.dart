library src;

import 'dart:convert';
import 'dart:typed_data';

String wrapAtPosition(String s, {int position = 64}) {
  if (position == 0) {
    return s;
  }
  final buffer = StringBuffer();
  for (var i = 0; i < s.length; i++) {
    if (i != 0 && i % position == 0) {
      buffer.write('\n');
    }
    buffer.write(String.fromCharCode(s.runes.elementAt(i)));
  }
  return buffer.toString();
}

List<Uint8List> chunk(Uint8List s, int chunkSize) {
  final chunked = <Uint8List>[];
  for (var i = 0; i < s.length; i += chunkSize) {
    final end = (i + chunkSize < s.length) ? i + chunkSize : s.length;
    chunked.add(s.sublist(i, end));
  }
  return chunked;
}

String base64RawEncode(List<int> bytes) =>
    base64Encode(bytes).replaceAll('=', '');

Uint8List base64RawDecode(String base64Raw) {
  if (base64Raw.length % 4 != 0) {
    return base64RawDecode('$base64Raw=');
  }
  return base64Decode(base64Raw);
}
