import 'dart:io';

import 'package:dage/dage.dart';
import 'package:dage/src/armor.dart';
import 'package:test/test.dart';

const armoredFile = '''-----BEGIN AGE ENCRYPTED FILE-----
VGhpcyBpcyBzb21lIHRleHQgdGhhdCBJIHR5cGVkIHNvIHRoYXQgdGhlIGJhc2U2
NCByZXByZXNlbnRhdGlvbiBpZiBpdCB3b3VsZCBzcGFuIG11bHRpcGxlIGxpbmVz
IGlmIGl0IHdhcyBzcGxpdCBpbnRvIHN0cmluZ3Mgb2YgbGVuZ3RoIDY0LCB3aXRo
IHBhZGRpbmc=
-----END AGE ENCRYPTED FILE-----
''';

final armoredFileBytes = armoredFile.codeUnits;

const content =
    'This is some text that I typed so that the base64 representation if it would span multiple lines if it was split into strings of length 64, with padding';

void main() {
  test('Can parse armored', () async {
    final result = armorDecoder.convert(armoredFileBytes);
    expect(result, content.codeUnits);
  });

  test('Fails when parsing prepended garbage', () async {
    expect(() => armorDecoder.convert(('garbage$armoredFile').codeUnits),
        throwsException);
  });

  test('Fails when parsing appended garbage', () async {
    expect(() => armorDecoder.convert(('${armoredFile}garbage').codeUnits),
        throwsException);
  });

  test('Can write armored', () async {
    final result = armorEncoder.convert(content.codeUnits);
    expect(String.fromCharCodes(result), armoredFile);
  });

  test('Armored file is armored', () async {
    expect(await isArmored(File('test/armored')), true);
  });

  test('Not armored file is not armored', () async {
    expect(await isArmored(File('test/not_armored')), false);
  });
}
