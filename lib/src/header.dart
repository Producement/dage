library age.src;

import 'dart:convert';
import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';

import 'plugin/encoding.dart';
import 'passphrase_provider.dart';
import 'stanza.dart';
import 'stream.dart';

class AgeHeader {
  static final _logger = Logger('AgeHeader');
  static const _version = 'age-encryption.org/v1';
  static const _macSeparator = '---';
  final List<AgeStanza> _stanzas;
  final String _mac;

  const AgeHeader._(this._stanzas, this._mac);

  List<AgeStanza> get stanzas => _stanzas;

  Future<String> get withoutMac => AgeHeader.headerWithoutMac(stanzas);

  static Future<AgeHeader> create(
      List<AgeStanza> stanzas, Uint8List symmetricFileKey) async {
    final mac =
        await _calculateMac(await headerWithoutMac(stanzas), symmetricFileKey);
    _logger.fine('Calculated mac: $mac');
    return AgeHeader._(stanzas, mac);
  }

  static Future<AgeHeader> parseContent(AgeStream content,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    final rawHeader = await content.header.stream.toList();
    final headerString = utf8.decode(rawHeader.flattened.toList());
    return parse(headerString, passphraseProvider: passphraseProvider);
  }

  static Future<AgeHeader> parse(String header,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    _logger.finer('Header\n$header');
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
    _logger.fine('Parsed mac: $mac');
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
    _logger.fine('Header without mac\n${header.toString()}');
    return header.toString();
  }

  Future<void> checkMac(Uint8List symmetricFileKey) async {
    final mac =
        await _calculateMac(await headerWithoutMac(_stanzas), symmetricFileKey);
    _logger.fine('Calculated mac: $mac, parsed mac: $_mac');
    if (mac != _mac) {
      throw Exception('Incorrect mac');
    }
  }

  static Future<String> _calculateMac(
      String header, Uint8List symmetricFileKey) async {
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    _logger.fine('Calculating MAC');
    final secretKeyData = SecretKeyData(symmetricFileKey);
    final macKey = await hkdfAlgorithm.deriveKey(
        secretKey: secretKeyData,
        nonce: Uint8List(1),
        info: 'header'.codeUnits);
    final mac = await hkdfAlgorithm.hmac
        .calculateMac(header.codeUnits, secretKey: macKey);
    return base64RawEncode(mac.bytes);
  }
}
