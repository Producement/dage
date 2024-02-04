import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;

import 'package:collection/collection.dart';
import 'package:dage/src/armor_parser.dart';

const _label = 'AGE ENCRYPTED FILE';
const _armorStart = '-----BEGIN $_label-----';
const _armorEnd = '-----END $_label-----';

final _codec = AgeArmorCodec();

class AgeArmorCodec extends Codec<List<int>, String> {
  @override
  Converter<String, List<int>> get decoder => AgeArmorDecoder();

  @override
  Converter<List<int>, String> get encoder => AgeArmorEncoder();
}

class AgeArmorDecoder extends Converter<String, List<int>> {
  @override
  List<int> convert(String input) {
    final result = decode(input);
    if (result.isEmpty) {
      throw NoArmorBlockFoundException._(input);
    }
    return result.first;
  }

  List<List<int>> decode(String armoredString) {
    final trimmed = armoredString.trim();
    if (!trimmed.startsWith(_armorStart)) {
      throw Exception('Armored file not valid');
    }
    if (!trimmed.endsWith(_armorEnd)) {
      throw Exception('Armored file not valid');
    }
    final result = <List<int>>[];
    for (final matches in armorParserMatches('$trimmed\n')) {
      final preLabel = matches[0];
      final data = matches[1];
      final postLabel = matches[2];

      if (preLabel != postLabel || _label != preLabel) {
        print('WHAT');
        continue;
      }

      result.add(base64.decode(data));
    }
    return result;
  }
}

class AgeArmorEncoder extends Converter<List<int>, String> {
  @override
  String convert(List<int> input) {
    final s = StringBuffer();
    s.writeln(_armorStart);
    final lines = base64.encode(input);
    for (var i = 0; i < lines.length; i += 64) {
      s.writeln(lines.substring(i, math.min(lines.length, i + 64)));
    }
    s.writeln(_armorEnd);
    return s.toString();
  }
}

Future<bool> isArmored(File file) async {
  final header = await file.openRead(0, _armorStart.length).toList();
  final eq = const ListEquality().equals;
  return eq(header.flattened.toList(), _armorStart.codeUnits);
}

Converter<List<int>, List<int>> get armorDecoder =>
    utf8.decoder.fuse(_codec.decoder);

Converter<List<int>, List<int>> get armorEncoder =>
    _codec.encoder.fuse(utf8.encoder);

class NoArmorBlockFoundException implements Exception {
  final String data;

  NoArmorBlockFoundException._(this.data);

  @override
  String toString() => 'No valid armor blocks were found in the data:\n$data';
}
