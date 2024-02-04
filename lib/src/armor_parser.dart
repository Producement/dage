// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
import 'package:petitparser/petitparser.dart';

final _cr = char('\x0d');
final _lf = char('\x0a');
final _eol = ignore((_cr & _lf) | _cr | _lf);

final _preeb =
    (string('-----BEGIN ') & string('AGE ENCRYPTED FILE') & string('-----'))
        .pick(1);
final _posteb =
    (string('-----END ') & string('AGE ENCRYPTED FILE') & string('-----'))
        .pick(1);
final _base64char = pattern('a-zA-Z0-9+/');
final _base64pad = char('=');

final _base64line = _base64char.times(64) & _eol;

final _base64singlePadSuffix = (_base64char.repeat(3) & _base64pad & _eol);
final _base64doublePadSuffix =
    (_base64char.repeat(2) & _base64pad.repeat(2) & _eol);

final _base64finl = _base64char.repeat(4).repeat(1, 15) &
        (_base64singlePadSuffix | _base64doublePadSuffix | _eol) |
    _base64singlePadSuffix |
    _base64doublePadSuffix;

final _base64text = flatten(
    (_base64line.plus() & _base64finl) | _base64line.star() | _base64finl);
final armorParser =
    (_preeb & _eol & _base64text & _posteb & _eol).permute([0, 2, 3]);

Iterable<List> armorParserMatches(String armoredString) {
  return armorParser.allMatches(armoredString, overlapping: false);
}

void _flattenString(dynamic value, StringBuffer target) {
  if (value == null) {
    return;
  }
  if (value is String) {
    target.write(value);
    return;
  }
  if (value is List) {
    for (final v in value) {
      _flattenString(v, target);
    }
    return;
  }
  throw ArgumentError('Unsupported type ${value.runtimeType}');
}

/// Create a [Parser] that ignores output from [p] and return `null`.
Parser<String?> ignore<T>(Parser<T> p) => p.map((_) => null);

/// Create a [Parser] that flattens all strings in the result from [p].
Parser<String> flatten(Parser<dynamic> p) => p.map((value) {
      final s = StringBuffer();
      _flattenString(value, s);
      return s.toString();
    });
