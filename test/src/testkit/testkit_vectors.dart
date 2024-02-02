import 'dart:io';
import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'package:dage/dage.dart';
import 'package:path/path.dart';

import '../fixture.dart';

class Vector {
  final String name;
  final Expect expect;
  final String? payload;
  final String? comment;
  final Future<List<AgeKeyPair>> identities;
  final Future<List<PassphraseProvider>> passphrases;
  final bool armored;
  final Uint8List body;

  Vector(this.name, this.expect, this.payload, this.comment, this.identities,
      this.passphrases, this.armored, this.body);

  Future<bool> get hasIdentities async => (await identities).isNotEmpty;

  Future<bool> get hasPassphrases async => (await passphrases).isNotEmpty;
}

enum Expect {
  success(value: 'success'),
  noMatch(value: 'no match'),
  hmacFailure(value: 'HMAC failure'),
  headerFailure(value: 'header failure'),
  payloadFailure(value: 'payload failure'),
  armorFailure(value: 'armor failure');

  const Expect({required this.value});

  final String value;

  static Expect? byValue(String value) {
    return Expect.values.firstWhereOrNull((element) => element.value == value);
  }
}

Future<List<PassphraseProvider>> _passphraseProviders(
    List<String> passphrases) async {
  return passphrases
      .map((passphrase) => ConstantPassphraseProvider(phrase: passphrase))
      .toList();
}

Future<List<AgeKeyPair>> _keyPairs(List<String> identities) async {
  final pairs = identities.map((identity) async {
    return await AgePlugin.convertIdentityToKeyPair(
        AgeIdentity.fromBech32(identity));
  }).toList();
  return Future.wait(pairs);
}

int _findConsecutiveNewlines(Uint8List byteList) {
  for (int i = 0; i < byteList.length - 1; i++) {
    if (byteList[i] == 10 && byteList[i + 1] == 10) {
      return i;
    }
  }
  return -1;
}

Map<String, List<String>> _parseHeader(String header) {
  final Map<String, List<String>> headerMap = {};
  for (final line in header.split('\n')) {
    final parts = line.split(': ');
    if (!headerMap.containsKey(parts[0])) {
      headerMap[parts[0]] = [parts[1]];
      continue;
    }
    headerMap[parts[0]]!.add(parts[1]);
  }
  return headerMap;
}

List<Vector> testVectors() {
  return Directory('testkit').listSync().whereType<File>().map((entity) {
    final contents = entity.readAsBytesSync();
    final sepIdx = _findConsecutiveNewlines(contents);
    final header = String.fromCharCodes(contents.sublist(0, sepIdx));
    final body = contents.sublist(sepIdx + 2);
    final headerMap = _parseHeader(header);
    return Vector(
        basename(entity.path),
        Expect.byValue(headerMap['expect']!.first)!,
        headerMap['payload']?.first,
        headerMap['comment']?.first,
        _keyPairs(headerMap['identity'] ?? []),
        _passphraseProviders(headerMap['passphrase'] ?? []),
        headerMap['armored']?.first == 'yes',
        body);
  }).toList();
}
