library age.src;

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
        for (final byte in bytes) {
          if (isPayload) {
            payloadBuffer.add(byte);
          } else {
            // Searching for a mac (newline followed by three dashes)
            if (!isMac) {
              if (byte == 0x0a) {
                index = 1;
                // Newline found
              } else if (byte == 0x2D && index > 0) {
                // Dash 1-3 found
                index++;
              } else if (index != 0) {
                // No dash or newline, reset state
                index = 0;
              }
              // Found a newline followed by three dashes, we found mac
              if (index == 4) {
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
      if (!isMac) {
        header.addError(Exception('Mac line not found in header!'));
      }
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
