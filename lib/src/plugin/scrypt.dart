library age.plugin;

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:pointycastle/key_derivators/scrypt.dart';
import 'package:pointycastle/pointycastle.dart';

import '../keypair.dart';
import '../passphrase_provider.dart';
import 'encoding.dart';
import 'plugin.dart';
import '../stanza.dart';

class ScryptPlugin extends AgePlugin {
  static const _info = 'age-encryption.org/v1/scrypt';
  static const _defaultWorkFactor = 18;

  const ScryptPlugin();

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [SimpleKeyPair? ephemeralKeyPair]) async {
    return null;
  }

  @override
  Future<AgeKeyPair?> identityToKeyPair(AgeIdentity identity) async {
    return null;
  }

  @override
  Future<AgeStanza?> parseStanza(List<String> arguments, List<int> body,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    if (arguments.isEmpty || arguments[0] != 'scrypt') {
      return null;
    }
    if (arguments.length != 3) {
      throw Exception('Wrong amount of arguments: ${arguments.length}!');
    }
    final salt = base64RawDecode(arguments[1]);
    if (salt.length != 16) {
      throw Exception('Salt size is incorrect!');
    }
    final workFactor = int.parse(arguments[2]);
    if (body.length != 32) {
      throw Exception('Body size is incorrect!');
    }
    return ScryptStanza(body, salt, workFactor, passphraseProvider);
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      List<int> symmetricFileKey, List<int> salt,
      {PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    final derivator = Scrypt();
    final parameters = ScryptParameters(pow(2, _defaultWorkFactor).toInt(), 8,
        1, 32, Uint8List.fromList(_info.codeUnits + salt));
    derivator.init(parameters);
    final passphrase = await passphraseProvider.passphrase();
    final derivedKey =
        derivator.process(Uint8List.fromList(passphrase.codeUnits));
    final wrappedKey =
        await AgeStanza.wrap(symmetricFileKey, SecretKey(derivedKey));
    return ScryptStanza(
        wrappedKey, salt, _defaultWorkFactor, passphraseProvider);
  }
}

class ScryptStanza extends AgeStanza {
  static const _algorithmTag = 'scrypt';
  final List<int> _wrappedKey;
  final List<int> _salt;
  final int _workFactor;
  final PassphraseProvider _passphraseProvider;

  ScryptStanza(
      this._wrappedKey, this._salt, this._workFactor, this._passphraseProvider);

  @override
  Future<Uint8List> decryptedFileKey(AgeKeyPair? keyPair) async {
    final derivator = Scrypt();
    final parameters = ScryptParameters(pow(2, _workFactor).toInt(), 8, 1, 32,
        Uint8List.fromList(ScryptPlugin._info.codeUnits + _salt));
    derivator.init(parameters);
    final passphrase = await _passphraseProvider.passphrase();
    final derivedKey =
        derivator.process(Uint8List.fromList(passphrase.codeUnits));
    return AgeStanza.unwrap(_wrappedKey, SecretKey(derivedKey));
  }

  @override
  Future<String> serialize() async {
    final header = '-> $_algorithmTag ${base64RawEncode(_salt)} $_workFactor';
    final body = base64RawEncode(_wrappedKey);
    return '${wrapAtPosition(header)}\n${wrapAtPosition(body)}';
  }
}
