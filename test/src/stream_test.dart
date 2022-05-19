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

  test('parses complex header', () async {
    final headerValue = '''age-encryption.org/v1
-> X25519 L+V9o0fNYkMVKNqsX7spBzD/9oSvxM/C7ZCZX1jLO3Q
5JB0/RnLXiJHL29Bg7V1kWZX5+WaM8KjNryAX74lJQg
-> scrypt zzYuo2y6OED2CG3D53V0fw 18
bDv3uo69Okm5eK3/EgDNcG2DJWng6CvAqIVEzxM4Qmo
--- B8KHU7wT6kOr8cgWResfbN3irfAO3yZpt0aoR026YHs''';
    final payloadValue = '''$headerValue
payload''';
    final stream = AgeStream(Stream.value(payloadValue.codeUnits));
    final header = await stream.header.stream.toList();
    final payload = await stream.payload.stream.toList();
    expect(String.fromCharCodes(payload.flattened), equals('payload'));
    expect(String.fromCharCodes(header.flattened), equals(headerValue));
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
