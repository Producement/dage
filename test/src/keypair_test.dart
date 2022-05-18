import 'package:test/test.dart';

import 'fixture.dart';

void main() {
  setUpAll(() => setupLogging());

  test('keypair to string', () async {
    expect(
        recipient.toString(),
        equals(
            'age12v6newahxev3mukn7tmr2ycvu5wa0tzkf2yuwret3j8mjg49mggqnawwlu'));
    expect(
        identity.toString(),
        equals(
            'AGE-SECRET-KEY-13W6UT6Z3H72N3YY9MXJMPPMN2K0KQGW863HPH258UCUXKLK3S3RQA32XH3'));
  });
}
