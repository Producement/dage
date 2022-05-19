import 'package:collection/collection.dart';
import 'package:dage/src/stream.dart';
import 'package:test/test.dart';

import 'fixture.dart';

void main() {
  setUpAll(() => setupLogging());

  test('parses header', () async {
    final stream = AgeStream(Stream.value('test\n---'.codeUnits));
    final header = await stream.header.stream.toList();
    final payload = await stream.payload.stream.toList();
    expect(header.flattened, equals('test\n---'.codeUnits));
    expect(payload.flattened, isEmpty);
  });

  test('parses payload after header, removes newline', () async {
    final stream = AgeStream(Stream.value('test\n---\npayload'.codeUnits));
    final header = await stream.header.stream.toList();
    final payload = await stream.payload.stream.toList();
    expect(header.flattened, equals('test\n---'.codeUnits));
    expect(payload.flattened, equals('payload'.codeUnits));
  });

  test('mac is part of the header', () async {
    final stream = AgeStream(Stream.value('test\n--- mac\npayload'.codeUnits));
    final header = await stream.header.stream.toList();
    final payload = await stream.payload.stream.toList();
    expect(String.fromCharCodes(header.flattened), equals('test\n--- mac'));
    expect(payload.flattened, equals('payload'.codeUnits));
  });
}
