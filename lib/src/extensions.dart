import 'dart:convert';
import 'dart:typed_data';

extension IntListExtensions on List<int> {
  String base64RawEncode() => base64Encode(this).replaceAll('=', '');

  List<Uint8List> chunk(int chunkSize) {
    final chunked = <Uint8List>[];
    for (var i = 0; i < length; i += chunkSize) {
      final end = (i + chunkSize < length) ? i + chunkSize : length;
      chunked.add(Uint8List.fromList(sublist(i, end)));
    }
    return chunked;
  }
}

extension StringExtensions on String {
  Uint8List base64RawDecode() {
    if (length % 4 != 0) {
      return '$this='.base64RawDecode();
    }
    return base64Decode(this);
  }

  String wrapAtPosition({int position = 64}) {
    if (position == 0) {
      return this;
    }
    final buffer = StringBuffer();
    for (var i = 0; i < length; i++) {
      if (i != 0 && i % position == 0) {
        buffer.write('\n');
      }
      buffer.write(String.fromCharCode(runes.elementAt(i)));
    }
    return buffer.toString();
  }
}
