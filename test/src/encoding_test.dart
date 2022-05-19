import 'package:dage/src/plugin/encoding.dart';
import 'package:test/test.dart';

void main() {
  test('raw base64 MUST reject normal base64 with padding', () async {
    expect(() => base64RawDecode('aGVsbG8='), throwsException);
  });

  test('can decode unpadded base64', () async {
    expect(base64RawDecode('aGVsbG8'), orderedEquals('hello'.codeUnits));
  });

  test('can encode bytes to raw base64', () async {
    expect(base64RawEncode('hello'.codeUnits), equals('aGVsbG8'));
  });
}
