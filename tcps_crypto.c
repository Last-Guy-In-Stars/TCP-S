#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/module.h>
#include <crypto/curve25519.h>
#include "tcps.h"

static inline uint32_t load_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

static inline uint32_t rotl32(uint32_t v, int n)
{
	return (v << n) | (v >> (32 - n));
}

#define QR(a, b, c, d) do {		 \
	a += b; d ^= a; d = rotl32(d, 16); \
	c += d; b ^= c; b = rotl32(b, 12); \
	a += b; d ^= a; d = rotl32(d, 8);  \
	c += d; b ^= c; b = rotl32(b, 7);  \
} while (0)

static void chacha20_block(uint32_t out[16], const uint32_t state[16])
{
	uint32_t w[16];
	int i;

	memcpy(w, state, 64);
	for (i = 0; i < 10; i++) {
		QR(w[0], w[4], w[8],  w[12]);
		QR(w[1], w[5], w[9],  w[13]);
		QR(w[2], w[6], w[10], w[14]);
		QR(w[3], w[7], w[11], w[15]);
		QR(w[0], w[5], w[10], w[15]);
		QR(w[1], w[6], w[11], w[12]);
		QR(w[2], w[7], w[8],  w[13]);
		QR(w[3], w[4], w[9],  w[14]);
	}
	for (i = 0; i < 16; i++)
		out[i] = w[i] + state[i];
	memzero_explicit(w, sizeof(w));
}

void chacha20_xor_stream(const uint8_t key[32], uint64_t pos,
			 uint8_t *data, uint32_t len)
{
	uint64_t block_num = pos / 64;
	uint32_t skip = (uint32_t)(pos % 64);
	uint32_t state[16] = {
		0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		load_le32(key),     load_le32(key + 4),
		load_le32(key + 8), load_le32(key + 12),
		load_le32(key + 16), load_le32(key + 20),
		load_le32(key + 24), load_le32(key + 28),
		(uint32_t)block_num, (uint32_t)(block_num >> 32),
		0, 0
	};
	uint8_t ks[64];
	uint32_t off = 0;
	uint32_t avail, chunk;
	int i;
	uint32_t j;

	if (skip > 0) {
		uint32_t blk[16];
		chacha20_block(blk, state);
		for (i = 0; i < 16; i++)
			store_le32(ks + i * 4, blk[i]);
		state[12]++;
		if (!state[12])
			state[13]++;
		avail = 64 - skip;
		chunk = avail < len ? avail : len;
		for (j = 0; j < chunk; j++)
			data[off++] ^= ks[skip + j];
	}

	while (off < len) {
		uint32_t blk[16];
		chacha20_block(blk, state);
		for (i = 0; i < 16; i++)
			store_le32(ks + i * 4, blk[i]);
		state[12]++;
		if (!state[12])
			state[13]++;
		chunk = len - off;
		if (chunk > 64)
			chunk = 64;
		for (j = 0; j < chunk; j++)
			data[off++] ^= ks[j];
	}

	memzero_explicit(state, sizeof(state));
	memzero_explicit(ks, sizeof(ks));
}

static void kdf_expand(const uint8_t prk[32], uint64_t position,
		       const char *label, uint8_t counter,
		       uint8_t out[32])
{
	uint8_t input[64];

	memset(input, 0, sizeof(input));
	memcpy(input, label, strlen(label));
	input[32] = counter;

	chacha20_xor_stream(prk, position, input, 64);
	memcpy(out, input, 32);
	memzero_explicit(input, sizeof(input));
}

void tcps_derive_keys(const uint8_t shared_secret[32], uint32_t client_isn,
		      uint32_t server_isn, int is_client,
		      uint8_t enc_key[32], uint8_t dec_key[32])
{
	uint8_t prk[32];
	uint8_t c2s_key[32], s2c_key[32];
	uint8_t extract_input[40];

	store_le32(extract_input, client_isn);
	store_le32(extract_input + 4, server_isn);
	memcpy(extract_input + 8, shared_secret, 32);

	memset(prk, 0, 32);
	chacha20_xor_stream(shared_secret, 0, extract_input, 40);
	memcpy(prk, extract_input, 32);

	kdf_expand(prk, (1ULL << 63), "TCPS c2s", 1, c2s_key);
	kdf_expand(prk, (1ULL << 63) | 64, "TCPS s2c", 2, s2c_key);

	if (is_client) {
		memcpy(enc_key, c2s_key, 32);
		memcpy(dec_key, s2c_key, 32);
	} else {
		memcpy(enc_key, s2c_key, 32);
		memcpy(dec_key, c2s_key, 32);
	}

	memzero_explicit(prk, sizeof(prk));
	memzero_explicit(c2s_key, sizeof(c2s_key));
	memzero_explicit(s2c_key, sizeof(s2c_key));
	memzero_explicit(extract_input, sizeof(extract_input));
}

int tcps_dh_shared(const uint8_t my_private[32], const uint8_t peer_public[32],
		   uint8_t shared[32])
{
	return curve25519(shared, my_private, peer_public);
}

void tcps_gen_keypair(uint8_t private_key[32], uint8_t public_key[32])
{
	curve25519_generate_secret(private_key);
	while (!curve25519_generate_public(public_key, private_key)) {
		curve25519_generate_secret(private_key);
	}
}
