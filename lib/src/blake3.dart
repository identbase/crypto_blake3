// Copyright 2023, the Blake3 project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'utils.dart';

/// An implementation of the [BLAKE3][blk3] hash function.
///
/// [blk3]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf 
const Hash blake3 = _Blake3._();

/// An implementation of the [BLAKE3][blk3] hash function.
///
/// [blk3]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf 
///
/// Use the [blake3] object to perform SHA-256 hashing.
class _Blake3 extends Hash {
  @override
  final int blockSize = 32 * bytesPerWord;

  const _Blake3._();

  @override
  ByteConversionSink startChunkedConversion(Sink<Digest> sink) =>
      ByteConversionSink.from(_Blake3Sink(sink));
}

/// The concrete implementation of [Blake3].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members
class _Blake3Sink implements Sink<List<int>> {

  /// Whether [close] has been called.
  bool _isClosed = false;

  @override
  void add(List<int> data) {

  }

  @override
  void close() {
    if (_isClosed) return;
    _isClosed = true; 
  }

  _Blake3Sink(Sink<Digest> sink);
}
