library age.src;

import 'dart:typed_data';

import 'package:bech32/bech32.dart';

class AgeKeyPair {
  final AgeIdentity? _identity;
  final AgeRecipient _recipient;

  const AgeKeyPair(this._identity, this._recipient);

  Uint8List? get identityBytes => _identity?.bytes;

  Uint8List get recipientBytes => _recipient.bytes;

  AgeRecipient get recipient => _recipient;
}

class AgeIdentity {
  final Uint8List _privateKey;
  final String _privateKeyPrefix;

  const AgeIdentity(this._privateKeyPrefix, this._privateKey);

  factory AgeIdentity.fromBech32(String bechPrivateKey) {
    final privateKey = Bech32Decoder().convert(bechPrivateKey);
    return AgeIdentity(privateKey.hrp,
        Uint8List.fromList(_convertBits(privateKey.data, 5, 8, false)));
  }

  @override
  String toString() =>
      _convertToBech32(_privateKeyPrefix, _privateKey).toUpperCase();

  Uint8List get bytes => _privateKey;
}

class AgeRecipient {
  final Uint8List _publicKey;
  final String _publicKeyPrefix;

  const AgeRecipient(this._publicKeyPrefix, this._publicKey);

  AgeKeyPair asKeyPair() => AgeKeyPair(null, this);

  @override
  String toString() => _convertToBech32(_publicKeyPrefix, _publicKey);

  Uint8List get bytes => _publicKey;

  String get prefix => _publicKeyPrefix;

  factory AgeRecipient.fromBech32(String bechPublicKey) {
    final publicKey = Bech32Decoder().convert(bechPublicKey);
    return AgeRecipient(publicKey.hrp,
        Uint8List.fromList(_convertBits(publicKey.data, 5, 8, false)));
  }
}

String _convertToBech32(String prefix, Uint8List key) {
  final bech32 = Bech32(prefix, _convertBits(key, 8, 5, true));
  return Bech32Encoder().convert(bech32);
}

List<int> _convertBits(List<int> data, int from, int to, bool pad) {
  var acc = 0;
  var bits = 0;
  var result = <int>[];
  var maxv = (1 << to) - 1;

  for (var v in data) {
    if (v < 0 || (v >> from) != 0) {
      throw Exception();
    }
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      result.add((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits > 0) {
      result.add((acc << (to - bits)) & maxv);
    }
  } else if (bits >= from) {
    throw InvalidPadding('illegal zero padding');
  } else if (((acc << (to - bits)) & maxv) != 0) {
    throw InvalidPadding('non zero');
  }

  return result;
}
