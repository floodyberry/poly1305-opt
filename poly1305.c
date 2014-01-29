#include <string.h>
#include "poly1305.h"

typedef struct poly1305_extension_t {
	size_t (*block_size)(void);
	void (*init_ext)(void *ctx, const poly1305_key *key, unsigned long long bytes_hint);
	void (*blocks)(void *ctx, const unsigned char *m, size_t bytes);
	void (*finish_ext)(void *ctx, const unsigned char *m, size_t remaining, unsigned char mac[16]);
	void (*auth)(unsigned char mac[16], const unsigned char *m, size_t bytes, const poly1305_key *key);
} poly1305_extension;


/* declare an extension */
#define DECLARE_POLY1305_EXTENSION(ext)                                                                             \
	size_t poly1305_block_size_##ext(void);                                                                         \
	void poly1305_init_ext_##ext(void *ctx, const poly1305_key *key, unsigned long long bytes_hint);                \
	void poly1305_blocks_##ext(void *ctx, const unsigned char *m, size_t bytes);                                    \
	void poly1305_finish_ext_##ext(void *ctx, const unsigned char *m, size_t remaining, unsigned char mac[16]);     \
	void poly1305_auth_##ext(unsigned char mac[16], const unsigned char *m, size_t bytes, const poly1305_key *key); \
	static const poly1305_extension poly1305_##ext = { \
		poly1305_block_size_##ext,                     \
		poly1305_init_ext_##ext,                       \
		poly1305_blocks_##ext,                         \
		poly1305_finish_ext_##ext,                     \
		poly1305_auth_##ext                            \
	};

#if !defined(POLY1305_IMPL)

#include "poly1305_config.inc"

/* reference implementation */
#define POLY1305_ONEFILE

DECLARE_POLY1305_EXTENSION(ref)

#if defined(POLY1305_EXT_REF_32)
	#include "extensions/poly1305_ref-32.c"
#elif defined(POLY1305_EXT_REF_8)
	#include "extensions/poly1305_ref-8.c"
#else
	#error Unable to find a suitable reference implementation! Did you run 'sh configure.sh'?
#endif

/* detect available extensions */
#define IS_X86_64 (defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(_M_X64))

#if defined(POLY1305_EXT_AVX2)
DECLARE_POLY1305_EXTENSION(avx2)
#endif

#if defined(POLY1305_EXT_AVX)
DECLARE_POLY1305_EXTENSION(avx)
#endif

#if defined(POLY1305_EXT_SSE2) && !(IS_X86_64)
DECLARE_POLY1305_EXTENSION(sse2)
#endif

#if defined(POLY1305_EXT_X86)
DECLARE_POLY1305_EXTENSION(x86)
#endif

/* best available primitives */
static const poly1305_extension *poly1305_best_ext = &poly1305_ref;
#else

#define DECLARE_SPECIFIC_EXTENSION2(ext) \
	DECLARE_POLY1305_EXTENSION(ext)     \
	static const poly1305_extension *poly1305_best_ext = &poly1305_##ext;

#define DECLARE_SPECIFIC_EXTENSION(ext) DECLARE_SPECIFIC_EXTENSION2(ext) 


DECLARE_SPECIFIC_EXTENSION(POLY1305_IMPL)

#endif

/* poly1305 implentation wrapped around provided primitives */
typedef struct poly1305_context_internal_t {
	unsigned char state[328]; /* largest state required (avx2) */
	unsigned char buffer[64];
	const poly1305_extension *ext;
	unsigned char leftover, block_size;
} poly1305_context_internal;

static poly1305_context_internal *
poly1305_get_context_internal(poly1305_context *ctx) {
	unsigned char *c = (unsigned char *)ctx;
	c += 63;
	c -= (size_t)c & 63;
	return (poly1305_context_internal *)c;
}

void
poly1305_init(poly1305_context *ctx, const poly1305_key *key) {
	poly1305_context_internal *ctxi = poly1305_get_context_internal(ctx);
	ctxi->ext = poly1305_best_ext;
	ctxi->ext->init_ext(ctxi, key, 0);
	ctxi->leftover = 0;
	ctxi->block_size = (unsigned char)ctxi->ext->block_size();
}

void
poly1305_init_ext(poly1305_context *ctx, const poly1305_key *key, unsigned long long bytes_hint) {
	poly1305_context_internal *ctxi = poly1305_get_context_internal(ctx);
	ctxi->ext = poly1305_best_ext;
	ctxi->ext->init_ext(ctxi, key, bytes_hint);
	ctxi->leftover = 0;
	ctxi->block_size = (unsigned char)ctxi->ext->block_size();
}

void
poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes) {
	poly1305_context_internal *ctxi = poly1305_get_context_internal(ctx);

	/* handle leftover */
	if (ctxi->leftover) {
		size_t want = (ctxi->block_size - ctxi->leftover);
		if (want > bytes)
			want = bytes;
		memcpy(ctxi->buffer + ctxi->leftover, m, want);
		bytes -= want;
		m += want;
		ctxi->leftover += want;
		if (ctxi->leftover < ctxi->block_size)
			return;
		ctxi->ext->blocks(ctxi, ctxi->buffer, ctxi->block_size);
		ctxi->leftover = 0;
	}

	/* process full blocks */
	if (bytes >= ctxi->block_size) {
		size_t want = (bytes & ~(ctxi->block_size - 1));
		ctxi->ext->blocks(ctxi, m, want);
		m += want;
		bytes -= want;
	}

	/* store leftover */
	if (bytes) {
		memcpy(ctxi->buffer + ctxi->leftover, m, bytes);
		ctxi->leftover += bytes;
	}
}

void
poly1305_finish(poly1305_context *ctx, unsigned char mac[16]) {
	poly1305_context_internal *ctxi = poly1305_get_context_internal(ctx);
	ctxi->ext->finish_ext(ctxi, ctxi->buffer, ctxi->leftover, mac);
}

void
poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const poly1305_key *key) {
	poly1305_best_ext->auth(mac, m, bytes, key);
}


/* test a few basic operations */
int
poly1305_power_on_self_test(void) {
	/* example from nacl */
	static const poly1305_key nacl_key = {{
		0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91,
		0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25,
		0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65,
		0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80,
	}};

	static const unsigned char nacl_msg[131] = {
		0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73,
		0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce,
		0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4,
		0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a,
		0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b,
		0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72,
		0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2,
		0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38,
		0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a,
		0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae,
		0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea,
		0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda,
		0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde,
		0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3,
		0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6,
		0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74,
		0xe3,0x55,0xa5
	};

	static const unsigned char nacl_mac[16] = {
		0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5,
		0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
	};

	/* generates a final value of (2^130 - 2) == 3 */
	static const poly1305_key wrap_key = {{
		0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	}};

	static const unsigned char wrap_msg[16] = {
		0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
	};

	static const unsigned char wrap_mac[16] = {
		0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};

	/*
		mac of the macs of messages of length 0 to 256, where the key and messages
		have all their values set to the length
	*/
	static const poly1305_key total_key = {{
		0x01,0x02,0x03,0x04,0x05,0x06,0x07,
		0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,
		0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		0xff,0xff,0xff,0xff,0xff,0xff,0xff
	}};

	static const unsigned char total_mac[16] = {
		0x64,0xaf,0xe2,0xe8,0xd6,0xad,0x7b,0xbd,
		0xd2,0x87,0xf9,0x7c,0x44,0x62,0x3d,0x39
	};

	poly1305_context ctx;
	poly1305_context total_ctx;
	poly1305_key all_key;
	unsigned char all_msg[256];
	unsigned char mac[16];
	size_t i, j;
	int result = 1;

	memset(mac, 0, sizeof(mac));
	poly1305_auth(mac, nacl_msg, sizeof(nacl_msg), &nacl_key);
	result &= (memcmp(nacl_mac, mac, sizeof(nacl_mac)) == 0);

	/* SSE2/AVX have a 32 byte block size, but also support 64 byte blocks, so
	   make sure everything still works varying between them */
	memset(mac, 0, sizeof(mac));
	poly1305_init(&ctx, &nacl_key);
	poly1305_update(&ctx, nacl_msg +   0, 32);
	poly1305_update(&ctx, nacl_msg +  32, 64);
	poly1305_update(&ctx, nacl_msg +  96, 16);
	poly1305_update(&ctx, nacl_msg + 112,  8);
	poly1305_update(&ctx, nacl_msg + 120,  4);
	poly1305_update(&ctx, nacl_msg + 124,  2);
	poly1305_update(&ctx, nacl_msg + 126,  1);
	poly1305_update(&ctx, nacl_msg + 127,  1);
	poly1305_update(&ctx, nacl_msg + 128,  1);
	poly1305_update(&ctx, nacl_msg + 129,  1);
	poly1305_update(&ctx, nacl_msg + 130,  1);
	poly1305_finish(&ctx, mac);
	result &= (memcmp(nacl_mac, mac, sizeof(nacl_mac)) == 0);

	memset(mac, 0, sizeof(mac));
	poly1305_auth(mac, wrap_msg, sizeof(wrap_msg), &wrap_key);
	result &= (memcmp(wrap_mac, mac, sizeof(nacl_mac)) == 0);

	poly1305_init(&total_ctx, &total_key);
	for (i = 0; i < 256; i++) {
		/* set key and message to 'i,i,i..' */
		for (j = 0; j < sizeof(all_key); j++)
			all_key.b[j] = i;
		for (j = 0; j < i; j++)
			all_msg[j] = i;
		poly1305_auth(mac, all_msg, i, &all_key);
		poly1305_update(&total_ctx, mac, 16);
	}
	poly1305_finish(&total_ctx, mac);
	result &= (memcmp(total_mac, mac, sizeof(total_mac)) == 0);

	return result;
}

#if !defined(POLY1305_IMPL)
/* extension selection & testing */
size_t poly1305_cpuid(void);

/* detect the best available implementation */
int
poly1305_detect(void) {
	int result = 1;
	size_t flags = poly1305_cpuid();

	poly1305_best_ext = &poly1305_ref; result &= poly1305_power_on_self_test();

#if defined(POLY1305_EXT_X86)
	#define cpuid_mmx    (1 <<  0)
	#define cpuid_sse    (1 <<  1)
	#define cpuid_sse2   (1 <<  2)
	#define cpuid_sse3   (1 <<  3)
	#define cpuid_ssse3  (1 <<  4)
	#define cpuid_sse4_1 (1 <<  5)
	#define cpuid_sse4_2 (1 <<  6)
	#define cpuid_avx    (1 <<  7)
	#define cpuid_xop    (1 <<  8)
	#define cpuid_avx2   (1 <<  9)

	poly1305_best_ext = &poly1305_x86; result &= poly1305_power_on_self_test();

#if defined(POLY1305_EXT_SSE2) && !(IS_X86_64)
	if (flags & cpuid_sse2) { poly1305_best_ext = &poly1305_sse2; result &= poly1305_power_on_self_test(); }
#endif

#if defined(POLY1305_EXT_AVX)
	if (flags & cpuid_avx) { poly1305_best_ext = &poly1305_avx; result &= poly1305_power_on_self_test(); }
#endif

#if defined(POLY1305_EXT_AVX2)
	if (flags & cpuid_avx2) { poly1305_best_ext = &poly1305_avx2; result &= poly1305_power_on_self_test(); }
#endif
#endif /* POLY1305_X86 */

	return result;
}
#else
int
poly1305_detect(void) {
	return poly1305_power_on_self_test();
}
#endif /* POLY1305_IMPL */

