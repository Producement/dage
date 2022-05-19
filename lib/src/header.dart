library src;

import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';

import 'extensions.dart';
import 'passphrase_provider.dart';
import 'stanza.dart';

class AgeHeader {
  static final logger = Logger('AgeHeader');
  static const _version = 'age-encryption.org/v1';
  static final _macSeparator = '---';
  final List<AgeStanza> _stanzas;
  final String _mac;

  AgeHeader._(this._stanzas, this._mac);

  List<AgeStanza> get stanzas => _stanzas;

  static Future<AgeHeader> create(
      List<AgeStanza> stanzas, Uint8List symmetricFileKey) async {
    final mac =
        await _calculateMac(await headerWithoutMac(stanzas), symmetricFileKey);
    logger.fine('Calculated mac: $mac');
    return AgeHeader._(stanzas, mac);
  }

  static Future<AgeHeader> parse(String header,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    logger.finer('Header: $header');
    final headerLines = header.split('\n');
    final versionLine = headerLines[0];
    if (versionLine != _version) {
      throw Exception('Unsupported version: $versionLine');
    }
    final stanzaContent = headerLines.sublist(1, headerLines.length - 1);
    final stanzaLines =
        stanzaContent.splitBefore((line) => line.startsWith('->'));
    final stanzas = await Future.wait(stanzaLines.map((e) =>
        AgeStanza.parse(e.join('\n'), passphraseProvider: passphraseProvider)));
    final mac = headerLines.last.replaceFirst('$_macSeparator ', '');
    logger.fine('Parsed mac: $mac');
    return AgeHeader._(stanzas.toList(), mac);
  }

  Future<String> serialize() async {
    return '${await headerWithoutMac(_stanzas)} $_mac';
  }

  static Future<String> headerWithoutMac(List<AgeStanza> stanzas) async {
    final header = StringBuffer();
    header.writeln(_version);
    for (var stanza in stanzas) {
      header.writeln(await stanza.serialize());
    }
    header.write(_macSeparator);
    return header.toString();
  }

  Future<void> checkMac(Uint8List symmetricFileKey) async {
    final mac =
        await _calculateMac(await headerWithoutMac(_stanzas), symmetricFileKey);
    logger.fine('Calculated mac: $mac, parsed mac: $_mac');
    assert(mac == _mac, 'Incorrect mac');
  }

  static Future<String> _calculateMac(
      String header, Uint8List symmetricFileKey) async {
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final secretKeyData = SecretKeyData(symmetricFileKey);
    final macKey = await hkdfAlgorithm.deriveKey(
        secretKey: secretKeyData,
        nonce: Uint8List(1),
        info: 'header'.codeUnits);
    final mac = await hkdfAlgorithm.hmac
        .calculateMac(header.codeUnits, secretKey: macKey);
    return mac.bytes.base64RawEncode();
  }
}
