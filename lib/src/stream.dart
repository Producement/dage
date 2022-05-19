import 'dart:async';

import 'package:logging/logging.dart';

class AgeStream {
  static final logger = Logger('AgeStream');
  final Stream<List<int>> _content;

  AgeStream(this._content) {
    var isPayload = false;
    var isMac = false;
    var index = 0;
    _content.listen((bytes) {
      if (isPayload) {
        payload.add(bytes);
      } else {
        final headerBuffer = <int>[];
        final payloadBuffer = <int>[];
        for (var byte in bytes) {
          if (isPayload) {
            payloadBuffer.add(byte);
          } else {
            if (!isMac) {
              if (byte == 0x0a && index == 0) {
                index++;
              } else if (byte == 0x2D && index > 0 && index < 3) {
                index++;
              } else {
                index = 0;
              }
              if (index == 3) {
                logger.fine(
                    'Found the mac line. Reading to header until newline.');
                isMac = true;
              }
              headerBuffer.add(byte);
            } else if (byte == 0x0a && isMac) {
              logger.fine('End of mac line. All following bytes are payload.');
              isPayload = true;
            } else {
              headerBuffer.add(byte);
            }
          }
        }
        header.add(headerBuffer);
        payload.add(payloadBuffer);
      }
    }, onDone: () {
      payload.close();
      header.close();
    }, onError: (e) {
      payload.addError(e);
      header.addError(e);
    });
  }

  final header = StreamController<List<int>>();
  final payload = StreamController<List<int>>();
}
