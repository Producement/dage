import 'package:dage/src/extensions.dart';
import 'package:test/test.dart';

void main() {
  test('raw base64 MUST reject normal base64 with padding', () async {
    expect(() => 'aGVsbG8='.base64RawDecode(), throwsException);
  });

  test('can decode unpadded base64', () async {
    expect('aGVsbG8'.base64RawDecode(), orderedEquals('hello'.codeUnits));
  });

  test('can encode bytes to raw base64', () async {
    expect('hello'.codeUnits.base64RawEncode(), equals('aGVsbG8'));
  });
}
