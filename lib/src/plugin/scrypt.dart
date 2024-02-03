library age.plugin;

import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:logging/logging.dart';
import 'package:pointycastle/key_derivators/scrypt.dart';
import 'package:pointycastle/pointycastle.dart';

import '../keypair.dart';
import '../passphrase_provider.dart';
import '../stanza.dart';
import 'encoding.dart';
import 'plugin.dart';

class ScryptPlugin extends AgePlugin {
  static final Logger _logger = Logger('ScryptPlugin');
  static const _info = 'age-encryption.org/v1/scrypt';
  static const _defaultWorkFactor = 18;

  const ScryptPlugin();

  @override
  Future<AgeStanza?> createStanza(
      AgeRecipient recipient, List<int> symmetricFileKey,
      [KeyPair? ephemeralKeyPair]) async {
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
    _logger.fine('Parsing stanza');
    if (arguments.isEmpty || arguments[0] != 'scrypt') {
      _logger.fine('Stanza is not scrypt');
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
    if (workFactor > 22 || workFactor < 1) {
      throw Exception('Work factor should be positive and less than 23!');
    }
    return ScryptStanza(body, salt, workFactor, passphraseProvider);
  }

  @override
  Future<AgeStanza?> createPassphraseStanza(
      List<int> symmetricFileKey, List<int> salt,
      {PassphraseProvider passphraseProvider = const PassphraseProvider(),
      int workFactor = _defaultWorkFactor}) async {
    _logger.fine('Creating Scrypt stanza with workfactor=$_defaultWorkFactor');
    final derivator = Scrypt();
    final actualWorkFactor = workFactor == -1 ? _defaultWorkFactor : workFactor;
    if (actualWorkFactor > 22 || actualWorkFactor < 1) {
      throw Exception('Work factor should be positive and less than 23!');
    }
    final parameters = ScryptParameters(pow(2, actualWorkFactor).toInt(), 8, 1,
        32, Uint8List.fromList(_info.codeUnits + salt));
    derivator.init(parameters);
    _logger.fine('Scrypt derivator initialised');
    final passphrase = await passphraseProvider.passphrase();
    _logger.fine('Deriving key');
    final derivedKey =
        derivator.process(Uint8List.fromList(passphrase.codeUnits));
    _logger.fine('Key derived');
    final wrappedKey =
        await AgeStanza.wrap(symmetricFileKey, SecretKey(derivedKey));
    return ScryptStanza(wrappedKey, salt, actualWorkFactor, passphraseProvider);
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
