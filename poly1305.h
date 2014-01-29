#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>

typedef unsigned char poly1305_context[512];

typedef struct poly1305_key_t {
	unsigned char b[32];
} poly1305_key;

int poly1305_detect(void);
int poly1305_power_on_self_test(void);

void poly1305_init(poly1305_context *ctx, const poly1305_key *key);
void poly1305_init_ext(poly1305_context *ctx, const poly1305_key *key, unsigned long long bytes_hint);
void poly1305_update(poly1305_context *ctx, const unsigned char *m, size_t bytes);
void poly1305_finish(poly1305_context *ctx, unsigned char mac[16]);

void poly1305_auth(unsigned char mac[16], const unsigned char *m, size_t bytes, const poly1305_key *key);


#endif /* POLY1305_H */

