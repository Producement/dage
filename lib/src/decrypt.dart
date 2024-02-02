library age.src;

import 'dart:typed_data';

import 'package:async/async.dart';
import 'package:cryptography/cryptography.dart';
import 'package:dage/src/stream.dart';
import 'package:logging/logging.dart';

import 'encrypt.dart';
import 'header.dart';
import 'keypair.dart';
import 'passphrase_provider.dart';

final Logger _logger = Logger('AgeDecrypt');

const _macSize = 16;

Stream<List<int>> decrypt(Stream<List<int>> content, List<AgeKeyPair> keyPairs,
    {PassphraseProvider passphraseProvider =
        const PassphraseProvider()}) async* {
  final split = AgeStream(content);
  final header = await AgeHeader.parseContent(split,
      passphraseProvider: passphraseProvider);
  Uint8List? symmetricFileKey;
  _logger.fine(
      'We have ${keyPairs.length} keypairs and ${header.stanzas.length} stanzas');
  for (var keyPair in keyPairs) {
    for (var stanza in header.stanzas) {
      try {
        symmetricFileKey = await stanza.decryptedFileKey(keyPair);
      } catch (e) {
        _logger.info('Keypair was not valid for this stanza');
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

Stream<List<int>> decryptWithPassphrase(Stream<List<int>> content,
    {PassphraseProvider passphraseProvider =
        const PassphraseProvider()}) async* {
  final split = AgeStream(content);
  final header = await AgeHeader.parseContent(split,
      passphraseProvider: passphraseProvider);
  if (header.stanzas.length != 1) {
    throw Exception('Only one recipient allowed!');
  }
  final stanza = header.stanzas.first;
  final symmetricFileKey = await stanza.decryptedFileKey(null);
  await header.checkMac(symmetricFileKey);
  yield* _decryptPayload(split.payload.stream,
      symmetricFileKey: symmetricFileKey);
}

List<int> _toBinaryCounter(int chunkCounter) {
  const byteCount = 11;
  final byteList = List<int>.filled(byteCount, 0);
  // Populate the list with bytes from the integer
  for (int i = byteCount - 1; i >= 0; i--) {
    // Extract each byte using bitwise operations
    byteList[i] = (chunkCounter & 0xFF);
    // Shift the integer to the right by 8 bits to process the next byte
    chunkCounter >>= 8;
  }
  return byteList;
}

Stream<List<int>> _decryptPayload(Stream<List<int>> payload,
    {required Uint8List symmetricFileKey}) async* {
  _logger.fine('Decrypting payload');
  final hkdfAlgorithm = Hkdf(
    hmac: Hmac(Sha256()),
    outputLength: 32,
  );
  final chunkedIterator = ChunkedStreamReader(payload);

  try {
    final payloadNonce = await chunkedIterator.readBytes(16);
    if (payloadNonce.isEmpty) {
      throw Exception('Payload nonce is missing!');
    }
    _logger.finer('Payload nonce: $payloadNonce');
    final payloadKey = await hkdfAlgorithm.deriveKey(
        secretKey: SecretKeyData(symmetricFileKey),
        nonce: payloadNonce,
        info: 'payload'.codeUnits);

    final encryptionAlgorithm = Chacha20.poly1305Aead();

    const chunkWithMacSize = chunkSize + _macSize;
    Uint8List chunk = await chunkedIterator.readBytes(chunkWithMacSize);
    Uint8List? nextChunk;
    int chunkCounter = 0;
    do {
      if (nextChunk != null) {
        chunk = nextChunk;
      }
      if (chunk.isEmpty && chunkCounter > 0) {
        break;
      }
      if (chunk.length < _macSize) {
        throw Exception('Incorrect chunk size!');
      }
      if (chunk.length == chunkWithMacSize) {
        nextChunk = await chunkedIterator.readBytes(chunkWithMacSize);
      }
      final nonceEnd =
          (chunk.length != chunkWithMacSize || nextChunk?.isNotEmpty != true)
              ? [0x01]
              : [0x00];
      final chunkNonce = _toBinaryCounter(chunkCounter) + nonceEnd;
      _logger.finer('Chunk nonce: $chunkNonce');
      _logger.finer('Chunk length: ${chunk.length}  (max: $chunkWithMacSize)');
      _logger.finer('Chunk mac: ${chunk.skip(chunk.length - _macSize)}');
      final secretBox = SecretBox.fromConcatenation(chunkNonce + chunk,
          nonceLength: 12, macLength: _macSize);
      final decrypted =
          await encryptionAlgorithm.decrypt(secretBox, secretKey: payloadKey);
      _logger.finer('Chunk decrypted');
      if (chunk.length != chunkWithMacSize &&
          decrypted.isEmpty &&
          chunkCounter != 0) {
        throw Exception('Last chunk can not be empty!');
      }
      chunkCounter = chunkCounter + 1;
      yield decrypted;
    } while (chunk.length == chunkWithMacSize);
  } finally {
    await chunkedIterator.cancel();
  }
  _logger.fine('Decryption finished');
}
