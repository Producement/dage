import 'package:collection/collection.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:dage/dage.dart';
import 'package:logging/logging.dart';
import 'package:test/test.dart';

import 'testkit_vectors.dart';

void main() async {
  Logger.root.level = Level.ALL;
  Logger.root.onRecord.listen((record) {
    print('${record.level.name}: ${record.time}: ${record.message}');
  });
  group('testkit', () {
    for (final vec in testVectors()) {
      if (vec.expect == Expect.success) {
        test('${vec.name} should succeed', () async {
          if (await vec.hasIdentities) {
            final Stream<List<int>> plaintext;
            if (vec.armored) {
              plaintext =
                  decryptArmored(Stream.value(vec.body), await vec.identities);
            } else {
              plaintext = decrypt(Stream.value(vec.body), await vec.identities);
            }
            final bytes = await plaintext.toList();
            expect(hex.encode(sha256.convert(List.from(bytes.flattened)).bytes),
                vec.payload,
                reason: vec.comment);
          } else {
            final Stream<List<int>> plaintext;
            if (vec.armored) {
              plaintext = decryptArmoredWithPassphrase(Stream.value(vec.body),
                  passphraseProvider: (await vec.passphrases).single);
            } else {
              plaintext = decryptWithPassphrase(Stream.value(vec.body),
                  passphraseProvider: (await vec.passphrases).single);
            }
            final bytes = await plaintext.toList();
            expect(hex.encode(sha256.convert(List.from(bytes.flattened)).bytes),
                vec.payload,
                reason: vec.comment);
          }
        });
      } else {
        test('${vec.name} should fail', () async {
          if (await vec.hasIdentities) {
            if (vec.armored) {
              await expectLater(
                  decryptArmored(Stream.value(vec.body), await vec.identities)
                      .toList(),
                  throwsException,
                  reason: vec.comment);
            } else {
              await expectLater(
                  decrypt(Stream.value(vec.body), await vec.identities)
                      .toList(),
                  throwsException,
                  reason: vec.comment);
            }
          } else {
            if (vec.armored) {
              await expectLater(
                  decryptArmoredWithPassphrase(Stream.value(vec.body),
                          passphraseProvider: (await vec.passphrases).first)
                      .toList(),
                  throwsException,
                  reason: vec.comment);
            } else {
              await expectLater(
                  decryptWithPassphrase(Stream.value(vec.body),
                          passphraseProvider: (await vec.passphrases).first)
                      .toList(),
                  throwsException,
                  reason: vec.comment);
            }
          }
        });
      }
    }
  });
}
