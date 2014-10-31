# ABOUT #

This is a portable, performant implementation of [Poly1305](http://cr.yp.to/mac.html), a "secret-key message-authentication code suitable for a wide variety of applications".

All assembler is PIC safe.

# INITIALIZING #

The library can be initialized, i.e. the most optimized implementation that passes internal tests will be automatically selected, in two ways, **neither of which are thread safe**:

1. `int poly1305_startup(void);` explicitly initializes the library, and returns a non-zero value if no suitable implementation is found that passes internal tests

2. Do nothing and use the library like normal. It will auto-initialize itself when needed, and hard exit if no suitable implementation is found.

# CALLING #

Common assumptions:

* When using the incremental functions, the `poly1305_state` struct is assumed to be word aligned, if necessary, for the system in use.

## ONE SHOT ##

`in` is assumed to be word aligned. Incremental support has no alignment requirements, but will obviously slow down if non word-aligned pointers are passed.

`void poly1305_auth(unsigned char *mac, const unsigned char *in, size_t inlen, const poly1305_key *key);`

Creates an authentictor in `mac` under the key `key` with `inlen` bytes from `in`.

## INCREMENTAL ##

Incremental `in` buffers are *not* required to be word aligned. Unaligned buffers will require copying to aligned buffers however, which will obviously incur a speed penalty.

`void poly1305_init(poly1305_state *S, const poly1305_key *key)`

Initializes `S` with the key `key`.

`void poly1305_init_ext(poly1305_state *S, const poly1305_key *key, size_t bytes_hint)`

Initializes `S` with the key `key`, and the hint that no more than `bytes_hint` will be authenticated. If more than `bytes_hint` bytes are passed, in total, the result _may_ be undefined.

`void poly1305_update(poly1305_state *S, const unsigned char *in, size_t inlen)`

Updates the state `S` with `inlen` bytes from `in` in.

`void poly1305_finish(poly1305_state *S, unsigned char *mac)`

Performs any finalizations on `S` and store the resulting authentictor in to `mac`.

# Examples #

## AUTHENTICATING DATA WITH ONE CALL ##

    size_t bytes = ...;
    unsigned char data[...] = {...};
    poly1305_key key = {{...}};
    unsigned char mac[16];

    poly1305_auth(mac, data, bytes, &key);

## HASHING INCREMENTALLY ##

Hashing incrementally, i.e. with multiple calls to update the state. 

    size_t bytes = ...;
    unsigned char data[...] = {...};
    poly1305_key key = {{...}};
    unsigned char mac[16];
    poly1305_state state;
    size_t i;

    poly1305_init(&state, &key);
    /* add one byte at a time, extremely inefficient */
    for (i = 0; i < bytes; i++) {
        poly1305_update(&state, data + i, 1);
    }
    poly1305_finish(&state, mac);


# VERSIONS #

## Reference ##

There are 3 reference versions, specialized for increasingly capable systems from 8 bit-ish only operations (with the world's most inefficient portable carries, you really don't want to use this unless nothing else runs) to 64 bit.

* Generic 8-bit-ish: [poly1305\_ref](app/extensions/poly1305/poly1305_ref-8.inc)
* Generic 32-bit with 64-bit compiler support: [poly1305\_ref](app/extensions/poly1305/poly1305_ref-32.inc)
* Generic 64-bit: [poly1305\_ref](app/extensions/poly1305/poly1305_ref-64.inc)

## x86 (32 bit) ##

* 386 compatible: [poly1305\_x86](app/extensions/poly1305/poly1305_x86-32.inc)
* SSE2: [poly1305\_sse2](app/extensions/poly1305/poly1305_sse2-32.inc)
* AVX: [poly1305\_avx](app/extensions/poly1305/poly1305_avx-32.inc)
* AVX2: [poly1305\_avx2](app/extensions/poly1305/poly1305_avx2-32.inc)

The 386 compatible version is a modified version of djb's floating point public domain implementation.

SSE2, AVX, and AVX2 versions of the one-shot version `poly1305_auth` will revert to the 386 compatible version if the number of bytes is below a certain threshhold.

## x86-64 ##

* x86-64 compatible: [poly1305\_x86](app/extensions/poly1305/poly1305_x86-64.inc)
* SSE2: [poly1305\_sse2](app/extensions/poly1305/poly1305_sse2-64.inc)
* AVX: [poly1305\_avx](app/extensions/poly1305/poly1305_avx-64.inc)
* AVX2: [poly1305\_avx2](app/extensions/poly1305/poly1305_avx2-64.inc)

SSE2, AVX, and AVX2 versions of the one-shot version `poly1305_auth` will revert to the x86-64 compatible version if the number of bytes is below a certain threshhold.

## ARM ##

* ARMv6: [blake2b\_armv6](app/extensions/blake2b/blake2b_armv6-32.inc)
* NEON: [blake2b\_avx](app/extensions/blake2b/blake2b_neon-32.inc)

NEON versions of the one-shot version `poly1305_auth` will revert to the ARMv6 version if the number of bytes is below a certain threshhold.



# BUILDING #

See [asm-opt#configuring](https://github.com/floodyberry/asm-opt#configuring) for full configure options.

If you would like to use Yasm with a gcc-compatible compiler, pass `--yasm` to configure.

The Visual Studio projects are generated assuming Yasm is available. You will need to have [Yasm.exe](http://yasm.tortall.net/Download.html) somewhere in your path to build them.

## STATIC LIBRARY ##

    ./configure
    make lib

and `make install-lib` OR copy `bin/poly1305.lib` and `app/include/poly1305.h` to your desired location.

## SHARED LIBRARY ##

    ./configure --pic
    make shared
    make install-shared

## UTILITIES / TESTING ##

    ./configure
    make util
    bin/poly1305-util [bench|fuzz]

### BENCHMARK / TESTING ###

Benchmarking will implicitly test every available version. If any fail, it will exit with an error indicating which versions did not pass. Features tested include:

* One-shot and Incremental authentication
* Results above 2^130 - 5 are properly normalized
* All potential block sizes in the underlying implementation are triggered

### FUZZING ###

Fuzzing tests every available implementation for the current CPU against the reference implementation. Features tested are:

* One-shot and Incremental authentication









# LICENSE #

Public Domain, or MIT