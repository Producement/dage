library src;

import 'dart:convert';
import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:collection/collection.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dage/src/stream.dart';
import 'package:logging/logging.dart';

import 'header.dart';
import 'keypair.dart';
import 'passphrase_provider.dart';
import 'plugin.dart';
import 'random.dart';
import 'stanza.dart';

class AgeFile {
  static final Logger logger = Logger('AgeFile');
  static final _chunkSize = 64 * 1024; //64KiB
  static final _macSize = 16;
  final Stream<List<int>> _content;
  final PassphraseProvider passphraseProvider;

  AgeFile(this._content,
      {this.passphraseProvider = const PassphraseProvider()});

  Stream<List<int>> get content => _content;

  Stream<List<int>> decrypt(List<AgeKeyPair> keyPairs) async* {
    final split = AgeStream(_content);
    final rawHeader = await split.header.stream.toList();
    final header = await AgeHeader.parse(
        utf8.decode(rawHeader.flattened.toList()),
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
    yield* _decryptPayload(split.payload.stream,
        symmetricFileKey: symmetricFileKey);
  }

  Stream<List<int>> decryptWithPassphrase() async* {
    final split = AgeStream(_content);
    final rawHeader = await split.header.stream.toList();
    final header = await AgeHeader.parse(
        utf8.decode(rawHeader.flattened.toList()),
        passphraseProvider: passphraseProvider);
    if (header.stanzas.length != 1) {
      throw Exception('Only one recipient allowed!');
    }
    final stanza = header.stanzas.first;
    Uint8List symmetricFileKey = await stanza.decryptedFileKey(null);
    await header.checkMac(symmetricFileKey);
    yield* _decryptPayload(split.payload.stream,
        symmetricFileKey: symmetricFileKey);
  }

  static Stream<List<int>> encryptWithPassphrase(Stream<List<int>> payload,
      {AgeRandom random = const AgeRandom(),
      PassphraseProvider passphraseProvider =
          const PassphraseProvider()}) async* {
    logger.fine('Encrypting to a passphrase');
    final symmetricFileKey = random.bytes(16);
    final stanza = await AgePlugin.passphraseStanzaCreate(
        symmetricFileKey, random.bytes(16), passphraseProvider);
    final header = await AgeHeader.create([stanza], symmetricFileKey);
    final payloadNonce = random.bytes(16);

    yield (await header.serialize()).codeUnits;
    yield [0x0a];
    yield* _encryptPayload(payload,
        symmetricFileKey: symmetricFileKey, payloadNonce: payloadNonce);
  }

  static Stream<List<int>> encrypt(
      Stream<List<int>> payload, List<AgeRecipient> recipients,
      {AgeRandom random = const AgeRandom(), SimpleKeyPair? keyPair}) async* {
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
    yield (await header.serialize()).codeUnits;
    yield [0x0a];
    yield* _encryptPayload(payload,
        symmetricFileKey: symmetricFileKey, payloadNonce: payloadNonce);
  }

  Stream<List<int>> _decryptPayload(Stream<List<int>> payload,
      {required Uint8List symmetricFileKey}) async* {
    logger.fine('Decrypting payload');
    final hkdfAlgorithm = Hkdf(
      hmac: Hmac(Sha256()),
      outputLength: 32,
    );
    final chunkedIterator = ChunkedStreamReader(payload);

    try {
      final payloadNonce = await chunkedIterator.readBytes(16);
      logger.finer('Payload nonce: $payloadNonce');
      final payloadKey = await hkdfAlgorithm.deriveKey(
          secretKey: SecretKeyData(symmetricFileKey),
          nonce: payloadNonce,
          info: 'payload'.codeUnits);
      final encryptionAlgorithm = Chacha20.poly1305Aead();

      final chunkWithMacSize = _chunkSize + _macSize;
      Uint8List chunk;
      do {
        chunk = await chunkedIterator.readBytes(chunkWithMacSize);
        final nonceEnd = (chunk.length != chunkWithMacSize) ? [0x01] : [0x00];
        final chunkNonce = List.generate(11, (index) => 0) + nonceEnd;
        logger.finer('Chunk nonce: $chunkNonce');
        logger.finer('Chunk length: ${chunk.length}  (max: $chunkWithMacSize)');
        logger.finer('Chunk mac: ${chunk.skip(chunk.length - _macSize)}');
        final secretBox = SecretBox.fromConcatenation(chunkNonce + chunk,
            nonceLength: 12, macLength: _macSize);
        final decrypted =
            await encryptionAlgorithm.decrypt(secretBox, secretKey: payloadKey);
        yield decrypted;
      } while (chunk.length == chunkWithMacSize);
    } finally {
      await chunkedIterator.cancel();
    }
    logger.fine('Decryption finished');
  }

  static Stream<List<int>> _encryptPayload(Stream<List<int>> payload,
      {required Uint8List symmetricFileKey,
      required Uint8List payloadNonce}) async* {
    yield payloadNonce;
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
    final chunkedIterator = ChunkedStreamReader(payload);
    try {
      Uint8List chunk;
      do {
        chunk = await chunkedIterator.readBytes(_chunkSize);
        final nonceEnd = (chunk.length != _chunkSize) ? [0x01] : [0x00];
        final chunkNonce = List.generate(11, (index) => 0) + nonceEnd;
        logger.finer('Chunk nonce: $chunkNonce');
        logger.finer('Chunk length: ${chunk.length} (max: $_chunkSize)');
        final secretBox = await encryptionAlgorithm.encrypt(chunk,
            nonce: chunkNonce, secretKey: payloadKey);
        logger.finer('Chunk mac: ${secretBox.mac.bytes}');
        yield secretBox.concatenation(nonce: false);
      } while (chunk.length == _chunkSize);
    } finally {
      await chunkedIterator.cancel();
    }
    logger.fine('Encryption finished');
  }
}
