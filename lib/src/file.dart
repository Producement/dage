library src;

import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dage/src/scrypt.dart';
import 'package:logging/logging.dart';

import 'header.dart';
import 'keypair.dart';
import 'plugin.dart';
import 'random.dart';
import 'stanza.dart';
import 'util.dart';

class AgeFile {
  static final Logger logger = Logger('AgeFile');
  final Uint8List _content;
  final PassphraseProvider passphraseProvider;

  AgeFile(this._content,
      {this.passphraseProvider = const PassphraseProvider()});

  Uint8List get content => _content;

  Future<Uint8List> decrypt(List<AgeKeyPair> keyPairs) async {
    final rawHeader = String.fromCharCodes(_content)
        .split('\n')
        .splitAfter((element) => element.startsWith('---'))
        .first
        .join('\n');

    final header = await AgeHeader.parse(rawHeader,
        passphraseProvider: passphraseProvider);
    Uint8List? symmetricFileKey;
    logger.fine(
        'We have ${keyPairs.length} keypairs and ${header.stanzas.length} stanzas');
    for (var keyPair in keyPairs) {
      for (var stanza in header.stanzas) {
        try {
          symmetricFileKey = await stanza.decryptedFileKey(keyPair);
        } catch (e, stacktrace) {
          logger.warning('Did not create key', e, stacktrace);
          //Ignore
        }
      }
    }
    if (symmetricFileKey == null) {
      throw Exception('Recipient not found');
    }
    await header.checkMac(symmetricFileKey);
    final payload = _content.skip(rawHeader.length + 1);
    return _decryptPayload(Uint8List.fromList(payload.toList()),
        symmetricFileKey: symmetricFileKey);
  }

  Future<Uint8List> decryptWithPassphrase() async {
    final rawHeader = String.fromCharCodes(_content)
        .split('\n')
        .splitAfter((element) => element.startsWith('---'))
        .first
        .join('\n');

    final header = await AgeHeader.parse(rawHeader,
        passphraseProvider: passphraseProvider);
    if (header.stanzas.length != 1) {
      throw Exception('Only one recipient allowed!');
    }
    final stanza = header.stanzas.first;
    Uint8List symmetricFileKey = await stanza.decryptedFileKey(null);
    await header.checkMac(symmetricFileKey);
    final payload = _content.skip(rawHeader.length + 1);
    return _decryptPayload(Uint8List.fromList(payload.toList()),
        symmetricFileKey: symmetricFileKey);
  }

  static Future<AgeFile> encryptWithPassphrase(Uint8List payload,
      {AgeRandom random = const AgeRandom(),
      PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async {
    logger.fine('Encrypting to a passphrase');
    final symmetricFileKey = random.bytes(16);
    final stanza = await AgePlugin.passphraseStanzaCreate(
        symmetricFileKey, random.bytes(16), passphraseProvider);
    final header = await AgeHeader.create([stanza], symmetricFileKey);
    final payloadNonce = random.bytes(16);
    return AgeFile(
        Uint8List.fromList((await header.serialize()).codeUnits +
            '\n'.codeUnits +
            await _encryptPayload(payload,
                symmetricFileKey: symmetricFileKey,
                payloadNonce: payloadNonce)),
        passphraseProvider: passphraseProvider);
  }

  static Future<AgeFile> encrypt(
      Uint8List payload, List<AgeRecipient> recipients,
      {AgeRandom random = const AgeRandom(), SimpleKeyPair? keyPair}) async {
    logger.fine('Encrypting to ${recipients.length} recipients');
    final symmetricFileKey = random.bytes(16);
    final stanzas =
        await Future.wait<AgeStanza>(recipients.map((recipient) async {
      return AgePlugin.stanzaCreate(recipient, symmetricFileKey, keyPair);
    }));
    if (stanzas.isEmpty) {
      throw Exception('Could not encrypt to any recipient!');
    }
    final header = await AgeHeader.create(stanzas, symmetricFileKey);
    final payloadNonce = random.bytes(16);
    return AgeFile(Uint8List.fromList((await header.serialize()).codeUnits +
        '\n'.codeUnits +
        await _encryptPayload(payload,
            symmetricFileKey: symmetricFileKey, payloadNonce: payloadNonce)));
  }

  Future<Uint8List> _decryptPayload(Uint8List payload,
      {required Uint8List symmetricFileKey}) async {
    logger.fine('Decrypting payload');
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final payloadNonce = payload.sublist(0, 16);
    logger.finer('Payload nonce: $payloadNonce');
    payload = payload.sublist(16);
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: payloadNonce,
        info: 'payload'.codeUnits);
    final encryptionAlgorithm = Chacha20.poly1305Aead();
    final chunkedContent = chunk(payload, 64 * 1024 + 16);
    logger.fine('Chunks: ${chunkedContent.length}');
    final decrypted =
        await Future.wait(chunkedContent.mapIndexed((i, chunk) async {
      final nonceEnd = i == (chunkedContent.length - 1) ? [0x01] : [0x00];
      final chunkNonce = List.generate(11, (index) => 0) + nonceEnd;
      logger.finer('Chunk nonce: $chunkNonce');
      logger.finer('Chunk length: ${chunk.length}');
      final secretBox = SecretBox.fromConcatenation(chunkNonce + chunk,
          nonceLength: 12, macLength: 16);
      final decrypted =
          await encryptionAlgorithm.decrypt(secretBox, secretKey: payloadKey);
      return Uint8List.fromList(decrypted);
    }));
    return decrypted
        .reduce((value, element) => Uint8List.fromList(value + element));
  }

  static Future<Uint8List> _encryptPayload(Uint8List payload,
      {required Uint8List symmetricFileKey,
      required Uint8List payloadNonce}) async {
    logger.fine('Encrypting payload');
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    logger.finer('Payload nonce: $payloadNonce');
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: payloadNonce,
        info: 'payload'.codeUnits);
    final encryptionAlgorithm = Chacha20.poly1305Aead();
    final chunkedContent = chunk(payload, 64 * 1024);
    logger.fine('Chunks: ${chunkedContent.length}');
    final encrypted =
        await Future.wait(chunkedContent.mapIndexed((i, chunk) async {
      final nonceEnd = i == (chunkedContent.length - 1) ? [0x01] : [0x00];
      final chunkNonce = List.generate(11, (index) => 0) + nonceEnd;
      logger.finer('Chunk nonce: $chunkNonce');
      logger.finer('Chunk length: ${chunk.length}');
      final secretBox = await encryptionAlgorithm.encrypt(chunk,
          nonce: chunkNonce, secretKey: payloadKey);
      return secretBox.concatenation(nonce: false);
    }));

    final joinEncrypted = encrypted
        .reduce((value, element) => Uint8List.fromList(value + element));
    return Uint8List.fromList(payloadNonce + joinEncrypted);
  }
}
