// Copyright 2023, the Blake3 project authors.  Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:ffi';
import 'dart:io' show Platform, Directory;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:path/path.dart' as path;
import 'package:typed_data/typed_data.dart';

import 'utils.dart';
import 'types.dart';


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
      ByteConversionSink.from(_Blake3Sink256(sink));
}

/// The concrete implementation of [Blake3].
///
/// This is separate so that it can extend [HashSink] without leaking additional
/// public members
class _Blake3Sink256 implements Sink<List<int>> {
  /// The inner sink that this should forward to.
  Sink<Digest> _sink;

  /// The dynamic library for [Blake3]
  late DynamicLibrary _hasher;

  /// Whether the hash function operates on big-endian words.
  late Endian _endian;

  /// The words in the current chunk.
  ///
  /// This is an instance variable to avoid re-allocating, but its data isn't
  /// used across invocations of [_iterate].
  late Uint32List _currentChunk;

  /// The length of the input data so far, in bytes.
  int _lengthInBytes = 0;

  /// Data that has yet to be processed by the hash function.
  final _pendingData = Uint8Buffer();

  /// Whether [close] has been called.
  bool _isClosed = false;

  /// The words in the current digest.
  ///
  /// This should be updated each time [updateHash] is called.
  Uint32List _digest;

  /// The number of signature bytes emitted at the end of the message.
  ///
  /// An encrypted message is followed by a signature which depends
  /// on the encryption algorithm used. This value specifies the
  /// number of bytes used by this signature. It must always be
  /// a power of 2 and no less than 8.
  late int _signatureBytes;

  @override
  void add(List<int> data) {
    if (_isClosed) throw StateError('Hash.add() called after close().');
    _lengthInBytes += data.length;
    _pendingData.addAll(data);
    _iterate();
  }

  @override
  void close() {
    _finalizeData();
    _iterate();
    assert(_pendingData.isEmpty);
    _sink.add(Digest(_byteDigest()));
    _sink.close();
  }

  Uint8List _byteDigest() {
    if (_endian == Endian.host) return _digest.buffer.asUint8List();

    // Cache the digest locally as `get` could be expensive.
    final cachedDigest = _digest;
    final byteDigest = Uint8List(cachedDigest.lengthInBytes);
    final byteData = byteDigest.buffer.asByteData();
    for (var i = 0; i < cachedDigest.length; i++) {
      byteData.setUint32(i * bytesPerWord, cachedDigest[i]);
    }
    return byteDigest;
  }


  /// Iterates through [_pendingData], updating the hash computation for each
  /// chunk.
  void _iterate() {
    var pendingDataBytes = _pendingData.buffer.asByteData();
    var pendingDataChunks = _pendingData.length ~/ _currentChunk.lengthInBytes;
    for (var i = 0; i < pendingDataChunks; i++) {
      // Copy words from the pending data buffer into the current chunk buffer.
      for (var j = 0; j < _currentChunk.length; j++) {
        _currentChunk[j] = pendingDataBytes.getUint32(
            i * _currentChunk.lengthInBytes + j * bytesPerWord, _endian);
      }

      // Run the hash function on the current chunk.
      updateHash(_currentChunk);
    }

    // Remove all pending data up to the last clean chunk break.
    _pendingData.removeRange(
        0, pendingDataChunks * _currentChunk.lengthInBytes);
  }

  /// Finalizes [_pendingData].
  ///
  /// This adds a 1 bit to the end of the message, and expands it with 0 bits to
  /// pad it out.
  void _finalizeData() { }

  /// Runs a single iteration of the hash computation, updating [digest] with
  /// the result.
  ///
  /// [chunk] is the current chunk, whose size is given by the
  /// `chunkSizeInWords` parameter passed to the constructor.
  void updateHash(Uint32List chunk) { }


  ///
  late HasherInit _init;

  ///
  late HasherUpdate _update;

  ///
  late HasherFinalize _finalize;


  _Blake3Sink256(this._sink, this._digest,
    int chunkSizeInWords,
    { Endian endian = Endian.big, int signatureBytes = 8 }) {

    _endian = endian;
    _signatureBytes = signatureBytes;
    assert(_signatureBytes >= 8);
    _currentChunk = Uint32List(chunkSizeInWords);

    var libraryPath =
        path.join(Directory.current.path, '../blake3_library', 'blake3_avx2_x86-64_windows_gnu.S');

    if (Platform.isMacOS) {
      libraryPath =
          path.join(Directory.current.path, '../blake3_library', 'blake3_avx2_x86-64_unix.S');
    }

    if (Platform.isWindows) {
      libraryPath = path.join(
          Directory.current.path, '../blake3_library', 'Debug', 'blake3_avx2_x86-64_windows_msvc.asm');
    }

    _hasher = DynamicLibrary.open(libraryPath);
    _init = _hasher
      .lookup<NativeFunction<HasherInitFunc>>('blake3_hasher_init')
      .asFunction();
    _update = _hasher
      .lookup<NativeFunction<HasherUpdateFunc>>('blake3_hasher_update')
      .asFunction();
    _finalize = _hasher
      .lookup<NativeFunction<HasherFinalizeFunc>>('blake3_hasher_finalize')
      .asFunction();



  }
}



