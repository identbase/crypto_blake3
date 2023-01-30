// AUTO GENERATED FILE, DO NOT EDIT.
//
// Generated by `package:ffigen`.
import 'dart:ffi' as ffi;

class Blake3 {
  /// Holds the symbol lookup function.
  final ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
      _lookup;

  /// The symbols are looked up in [dynamicLibrary].
  Blake3(ffi.DynamicLibrary dynamicLibrary) : _lookup = dynamicLibrary.lookup;

  /// The symbols are looked up with [lookup].
  Blake3.fromLookup(
      ffi.Pointer<T> Function<T extends ffi.NativeType>(String symbolName)
          lookup)
      : _lookup = lookup;

  void blake3_hasher_init(
    ffi.Pointer<blake3_hasher> self,
  ) {
    return _blake3_hasher_init(
      self,
    );
  }

  late final _blake3_hasher_initPtr = _lookup<
          ffi.NativeFunction<ffi.Void Function(ffi.Pointer<blake3_hasher>)>>(
      'blake3_hasher_init');
  late final _blake3_hasher_init = _blake3_hasher_initPtr
      .asFunction<void Function(ffi.Pointer<blake3_hasher>)>();

  void blake3_hasher_init_keyed(
    ffi.Pointer<blake3_hasher> self,
    ffi.Pointer<ffi.Uint8> key,
  ) {
    return _blake3_hasher_init_keyed(
      self,
      key,
    );
  }

  late final _blake3_hasher_init_keyedPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<blake3_hasher>,
              ffi.Pointer<ffi.Uint8>)>>('blake3_hasher_init_keyed');
  late final _blake3_hasher_init_keyed =
      _blake3_hasher_init_keyedPtr.asFunction<
          void Function(ffi.Pointer<blake3_hasher>, ffi.Pointer<ffi.Uint8>)>();

  void blake3_hasher_init_derive_key(
    ffi.Pointer<blake3_hasher> self,
    ffi.Pointer<ffi.Char> context,
  ) {
    return _blake3_hasher_init_derive_key(
      self,
      context,
    );
  }

  late final _blake3_hasher_init_derive_keyPtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<blake3_hasher>,
              ffi.Pointer<ffi.Char>)>>('blake3_hasher_init_derive_key');
  late final _blake3_hasher_init_derive_key =
      _blake3_hasher_init_derive_keyPtr.asFunction<
          void Function(ffi.Pointer<blake3_hasher>, ffi.Pointer<ffi.Char>)>();

  void blake3_hasher_update(
    ffi.Pointer<blake3_hasher> self,
    ffi.Pointer<ffi.Void> input,
    int input_len,
  ) {
    return _blake3_hasher_update(
      self,
      input,
      input_len,
    );
  }

  late final _blake3_hasher_updatePtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<blake3_hasher>, ffi.Pointer<ffi.Void>,
              ffi.Size)>>('blake3_hasher_update');
  late final _blake3_hasher_update = _blake3_hasher_updatePtr.asFunction<
      void Function(ffi.Pointer<blake3_hasher>, ffi.Pointer<ffi.Void>, int)>();

  void blake3_hasher_finalize(
    ffi.Pointer<blake3_hasher> self,
    ffi.Pointer<ffi.Void> out,
    int out_len,
  ) {
    return _blake3_hasher_finalize(
      self,
      out,
      out_len,
    );
  }

  late final _blake3_hasher_finalizePtr = _lookup<
      ffi.NativeFunction<
          ffi.Void Function(ffi.Pointer<blake3_hasher>, ffi.Pointer<ffi.Void>,
              ffi.Size)>>('blake3_hasher_finalize');
  late final _blake3_hasher_finalize = _blake3_hasher_finalizePtr.asFunction<
      void Function(ffi.Pointer<blake3_hasher>, ffi.Pointer<ffi.Void>, int)>();
}

class __mbstate_t extends ffi.Union {
  @ffi.Array.multi([128])
  external ffi.Array<ffi.Char> __mbstate8;

  @ffi.LongLong()
  external int _mbstateL;
}

class __darwin_pthread_handler_rec extends ffi.Struct {
  external ffi
          .Pointer<ffi.NativeFunction<ffi.Void Function(ffi.Pointer<ffi.Void>)>>
      __routine;

  external ffi.Pointer<ffi.Void> __arg;

  external ffi.Pointer<__darwin_pthread_handler_rec> __next;
}

class _opaque_pthread_attr_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([56])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_cond_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([40])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_condattr_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([8])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_mutex_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([56])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_mutexattr_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([8])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_once_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([8])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_rwlock_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([192])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_rwlockattr_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  @ffi.Array.multi([16])
  external ffi.Array<ffi.Char> __opaque;
}

class _opaque_pthread_t extends ffi.Struct {
  @ffi.Long()
  external int __sig;

  external ffi.Pointer<__darwin_pthread_handler_rec> __cleanup_stack;

  @ffi.Array.multi([8176])
  external ffi.Array<ffi.Char> __opaque;
}

class _blake3_chunk_state extends ffi.Struct {
  @ffi.Array.multi([8])
  external ffi.Array<ffi.Uint32> chaining_value;

  @ffi.Uint64()
  external int chunk_counter;

  @ffi.Array.multi([64])
  external ffi.Array<ffi.Uint8> block;

  @ffi.Uint8()
  external int block_len;

  @ffi.Uint8()
  external int blocks_compressed;

  @ffi.Uint32()
  external int flags;
}

class blake3_hasher extends ffi.Struct {
  external _blake3_chunk_state chunk_state;

  @ffi.Array.multi([8])
  external ffi.Array<ffi.Uint32> key_words;

  @ffi.Array.multi([432])
  external ffi.Array<ffi.Uint32> cv_stack;

  @ffi.Uint8()
  external int cv_stack_len;

  @ffi.Uint32()
  external int flags;
}

const int __DARWIN_ONLY_64_BIT_INO_T = 1;

const int __DARWIN_ONLY_UNIX_CONFORMANCE = 1;

const int __DARWIN_ONLY_VERS_1050 = 1;

const int __DARWIN_UNIX03 = 1;

const int __DARWIN_64_BIT_INO_T = 1;

const int __DARWIN_VERS_1050 = 1;

const int __DARWIN_NON_CANCELABLE = 0;

const String __DARWIN_SUF_EXTSN = '\$DARWIN_EXTSN';

const int __DARWIN_C_ANSI = 4096;

const int __DARWIN_C_FULL = 900000;

const int __DARWIN_C_LEVEL = 900000;

const int __STDC_WANT_LIB_EXT1__ = 1;

const int __DARWIN_NO_LONG_LONG = 0;

const int _DARWIN_FEATURE_64_BIT_INODE = 1;

const int _DARWIN_FEATURE_ONLY_64_BIT_INODE = 1;

const int _DARWIN_FEATURE_ONLY_VERS_1050 = 1;

const int _DARWIN_FEATURE_ONLY_UNIX_CONFORMANCE = 1;

const int _DARWIN_FEATURE_UNIX_CONFORMANCE = 3;

const int __has_ptrcheck = 0;

const int __DARWIN_NULL = 0;

const int __PTHREAD_SIZE__ = 8176;

const int __PTHREAD_ATTR_SIZE__ = 56;

const int __PTHREAD_MUTEXATTR_SIZE__ = 8;

const int __PTHREAD_MUTEX_SIZE__ = 56;

const int __PTHREAD_CONDATTR_SIZE__ = 8;

const int __PTHREAD_COND_SIZE__ = 40;

const int __PTHREAD_ONCE_SIZE__ = 8;

const int __PTHREAD_RWLOCK_SIZE__ = 192;

const int __PTHREAD_RWLOCKATTR_SIZE__ = 16;

const int __DARWIN_WCHAR_MAX = 2147483647;

const int __DARWIN_WCHAR_MIN = -2147483648;

const int _FORTIFY_SOURCE = 2;

const int NULL = 0;

const int __WORDSIZE = 64;

const int INT8_MAX = 127;

const int INT16_MAX = 32767;

const int INT32_MAX = 2147483647;

const int INT64_MAX = 9223372036854775807;

const int INT8_MIN = -128;

const int INT16_MIN = -32768;

const int INT32_MIN = -2147483648;

const int INT64_MIN = -9223372036854775808;

const int UINT8_MAX = 255;

const int UINT16_MAX = 65535;

const int UINT32_MAX = 4294967295;

const int UINT64_MAX = -1;

const int INT_LEAST8_MIN = -128;

const int INT_LEAST16_MIN = -32768;

const int INT_LEAST32_MIN = -2147483648;

const int INT_LEAST64_MIN = -9223372036854775808;

const int INT_LEAST8_MAX = 127;

const int INT_LEAST16_MAX = 32767;

const int INT_LEAST32_MAX = 2147483647;

const int INT_LEAST64_MAX = 9223372036854775807;

const int UINT_LEAST8_MAX = 255;

const int UINT_LEAST16_MAX = 65535;

const int UINT_LEAST32_MAX = 4294967295;

const int UINT_LEAST64_MAX = -1;

const int INT_FAST8_MIN = -128;

const int INT_FAST16_MIN = -32768;

const int INT_FAST32_MIN = -2147483648;

const int INT_FAST64_MIN = -9223372036854775808;

const int INT_FAST8_MAX = 127;

const int INT_FAST16_MAX = 32767;

const int INT_FAST32_MAX = 2147483647;

const int INT_FAST64_MAX = 9223372036854775807;

const int UINT_FAST8_MAX = 255;

const int UINT_FAST16_MAX = 65535;

const int UINT_FAST32_MAX = 4294967295;

const int UINT_FAST64_MAX = -1;

const int INTPTR_MAX = 9223372036854775807;

const int INTPTR_MIN = -9223372036854775808;

const int UINTPTR_MAX = -1;

const int INTMAX_MAX = 9223372036854775807;

const int UINTMAX_MAX = -1;

const int INTMAX_MIN = -9223372036854775808;

const int PTRDIFF_MIN = -9223372036854775808;

const int PTRDIFF_MAX = 9223372036854775807;

const int SIZE_MAX = -1;

const int RSIZE_MAX = 9223372036854775807;

const int WCHAR_MAX = 2147483647;

const int WCHAR_MIN = -2147483648;

const int WINT_MIN = -2147483648;

const int WINT_MAX = 2147483647;

const int SIG_ATOMIC_MIN = -2147483648;

const int SIG_ATOMIC_MAX = 2147483647;

const int BLAKE3_OUT_LEN = 32;

const int BLAKE3_KEY_LEN = 32;

const int BLAKE3_BLOCK_LEN = 64;

const int BLAKE3_CHUNK_LEN = 1024;
