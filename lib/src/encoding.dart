library age.plugin;

import 'dart:convert';
import 'dart:typed_data';

String base64RawEncode(List<int> data) =>
    base64Encode(data).replaceAll('=', '');

List<List<int>> chunked(List<int> data, int chunkSize) {
  final chunked = <List<int>>[];
  for (var i = 0; i < data.length; i += chunkSize) {
    final end = (i + chunkSize < data.length) ? i + chunkSize : data.length;
    chunked.add(data.sublist(i, end));
  }
  return chunked;
}

Uint8List base64RawDecode(String data) {
  if (data.contains('=')) {
    throw Exception('Padded base64 not supported!');
  }
  if (data.length % 4 != 0) {
    return base64Decode(
        '$data${List.generate(4 - data.length % 4, (index) => '=').join()}');
  }
  return base64Decode(data);
}

String wrapAtPosition(String data, {int position = 64}) {
  if (position == 0) {
    return data;
  }
  final buffer = StringBuffer();
  for (var i = 0; i < data.length; i++) {
    if (i != 0 && i % position == 0) {
      buffer.write('\n');
    }
    buffer.write(String.fromCharCode(data.runes.elementAt(i)));
  }
  return buffer.toString();
}
