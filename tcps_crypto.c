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

static inline void store_le64(uint8_t *p, uint64_t v)
{
	store_le32(p, (uint32_t)v);
	store_le32(p + 4, (uint32_t)(v >> 32));
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
}

void chacha20_xor_stream(const uint8_t key[32], uint64_t pos,
			 uint8_t *data, size_t len)
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
	size_t off = 0;
	size_t avail, chunk;
	int i;
	size_t j;

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

void tcps_dh_keygen(uint8_t priv[TCPS_DH_SIZE], uint8_t pub[TCPS_DH_SIZE])
{
	int retries = 0;

	get_random_bytes(priv, TCPS_DH_SIZE);
	curve25519_clamp_secret(priv);
	while (!curve25519_generate_public(pub, priv)) {
		get_random_bytes(priv, TCPS_DH_SIZE);
		curve25519_clamp_secret(priv);
		if (++retries > 10) {
			memset(pub, 0, TCPS_DH_SIZE);
			return;
		}
	}
}

int tcps_dh_shared(const uint8_t priv[TCPS_DH_SIZE],
		   const uint8_t peer_pub[TCPS_DH_SIZE],
		   uint8_t shared[TCPS_DH_SIZE])
{
	if (!curve25519(shared, priv, peer_pub))
		return -1;
	return 0;
}

static void tcps_kdf_expand(const uint8_t prk[TCPS_KEY_SIZE],
			    uint64_t position,
			    const char *label, uint8_t counter,
			    uint32_t client_isn, uint32_t server_isn,
			    uint8_t out[TCPS_KEY_SIZE])
{
	uint8_t input[64];

	memset(input, 0, sizeof(input));
	memcpy(input, label, strlen(label));
	input[32] = (uint8_t)(client_isn >> 24);
	input[33] = (uint8_t)(client_isn >> 16);
	input[34] = (uint8_t)(client_isn >> 8);
	input[35] = (uint8_t)(client_isn);
	input[36] = (uint8_t)(server_isn >> 24);
	input[37] = (uint8_t)(server_isn >> 16);
	input[38] = (uint8_t)(server_isn >> 8);
	input[39] = (uint8_t)(server_isn);
	input[40] = counter;

	chacha20_xor_stream(prk, position, input, 64);
	memcpy(out, input, TCPS_KEY_SIZE);
	memzero_explicit(input, sizeof(input));
}

void tcps_derive_session_keys(const uint8_t shared[TCPS_DH_SIZE],
			      uint32_t client_isn, uint32_t server_isn,
			      uint8_t key_c2s[TCPS_KEY_SIZE],
			      uint8_t key_s2c[TCPS_KEY_SIZE],
			      uint8_t mac_c2s[TCPS_KEY_SIZE],
			      uint8_t mac_s2c[TCPS_KEY_SIZE])
{
	tcps_kdf_expand(shared, (1ULL << 63) | 0, "TCPS enc_c2s", 1,
			client_isn, server_isn, key_c2s);
	tcps_kdf_expand(shared, (1ULL << 63) | 64, "TCPS enc_s2c", 2,
			client_isn, server_isn, key_s2c);
	tcps_kdf_expand(shared, (1ULL << 63) | 128, "TCPS mac_c2s", 3,
			client_isn, server_isn, mac_c2s);
	tcps_kdf_expand(shared, (1ULL << 63) | 192, "TCPS mac_s2c", 4,
			client_isn, server_isn, mac_s2c);
}

struct poly1305_ctx {
	uint32_t h[5];
	uint32_t r[5];
	uint32_t s[4];
};

static void poly1305_init(struct poly1305_ctx *ctx, const uint8_t key[32])
{
	ctx->r[0] = load_le32(key + 0) & 0x03ffffff;
	ctx->r[1] = (load_le32(key + 3) >> 2) & 0x03ffff03;
	ctx->r[2] = (load_le32(key + 6) >> 4) & 0x03ffc0ff;
	ctx->r[3] = (load_le32(key + 9) >> 6) & 0x03f03fff;
	ctx->r[4] = (load_le32(key + 12) >> 8) & 0x000fffff;

	ctx->s[0] = load_le32(key + 16);
	ctx->s[1] = load_le32(key + 20);
	ctx->s[2] = load_le32(key + 24);
	ctx->s[3] = load_le32(key + 28);

	memset(ctx->h, 0, sizeof(ctx->h));
}

static void poly1305_block(struct poly1305_ctx *ctx, const uint8_t m[16],
			   int is_final)
{
	uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2];
	uint32_t r3 = ctx->r[3], r4 = ctx->r[4];
	uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
	uint32_t h3 = ctx->h[3], h4 = ctx->h[4];
	uint64_t d0, d1, d2, d3, d4;
	uint32_t c;

	h0 += load_le32(m + 0) & 0x03ffffff;
	h1 += (load_le32(m + 3) >> 2) & 0x03ffffff;
	h2 += (load_le32(m + 6) >> 4) & 0x03ffffff;
	h3 += (load_le32(m + 9) >> 6) & 0x03ffffff;
	h4 += (load_le32(m + 12) >> 8);
	if (is_final)
		h4 += (1 << 24);

	d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 +
	     (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
	d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 +
	     (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
	d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 +
	     (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
	d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 +
	     (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
	d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 +
	     (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

	c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x03ffffff;
	d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x03ffffff;
	d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x03ffffff;
	d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x03ffffff;
	d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x03ffffff;
	h0 += c * 5;

	ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
	ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly1305_finish(struct poly1305_ctx *ctx, uint8_t tag[16])
{
	uint32_t h0, h1, h2, h3, h4, c, g0, g1, g2, g3, g4;
	uint32_t mask;
	uint64_t f;

	h0 = ctx->h[0]; h1 = ctx->h[1]; h2 = ctx->h[2];
	h3 = ctx->h[3]; h4 = ctx->h[4];

	c = (h0 >> 26); h0 &= 0x03ffffff;
	h1 += c; c = (h1 >> 26); h1 &= 0x03ffffff;
	h2 += c; c = (h2 >> 26); h2 &= 0x03ffffff;
	h3 += c; c = (h3 >> 26); h3 &= 0x03ffffff;
	h4 += c; c = (h4 >> 26); h4 &= 0x03ffffff;
	h0 += c * 5; c = (h0 >> 26); h0 &= 0x03ffffff; h1 += c;

	g0 = h0 + 5; c = (g0 >> 26); g0 &= 0x03ffffff;
	g1 = h1 + c; c = (g1 >> 26); g1 &= 0x03ffffff;
	g2 = h2 + c; c = (g2 >> 26); g2 &= 0x03ffffff;
	g3 = h3 + c; c = (g3 >> 26); g3 &= 0x03ffffff;
	g4 = h4 + c - (1 << 24);

	mask = (uint32_t)((int64_t)g4 >> 63);
	h0 = (h0 & ~mask) | (g0 & mask);
	h1 = (h1 & ~mask) | (g1 & mask);
	h2 = (h2 & ~mask) | (g2 & mask);
	h3 = (h3 & ~mask) | (g3 & mask);

	f = (uint64_t)h0 + ctx->s[0]; store_le32(tag, (uint32_t)f);
	f = (uint64_t)h1 + ctx->s[1] + (f >> 32); store_le32(tag + 4, (uint32_t)f);
	f = (uint64_t)h2 + ctx->s[2] + (f >> 32); store_le32(tag + 8, (uint32_t)f);
	f = (uint64_t)h3 + ctx->s[3] + (f >> 32); store_le32(tag + 12, (uint32_t)f);
}

void tcps_compute_mac(const uint8_t mac_key[TCPS_KEY_SIZE],
		      uint64_t seq, uint8_t tcp_flags,
		      const uint8_t *data, size_t len,
		      uint8_t tag[TCPS_MAC_TAG_SIZE])
{
	tcps_compute_mac_prefix(mac_key, seq, tcp_flags, NULL, 0, data, len, tag);
}

void tcps_compute_mac_prefix(const uint8_t mac_key[TCPS_KEY_SIZE],
			     uint64_t seq, uint8_t tcp_flags,
			     const uint8_t *prefix, size_t prefix_len,
			     const uint8_t *data, size_t data_len,
			     uint8_t tag[TCPS_MAC_TAG_SIZE])
{
	uint8_t poly_key[32];
	uint8_t full_tag[16];
	uint8_t aad[16];
	uint8_t pad[16];
	struct poly1305_ctx ctx;
	size_t i;
	size_t n;
	size_t total_len = prefix_len + data_len;

	memset(poly_key, 0, 32);
	chacha20_xor_stream(mac_key, ((uint64_t)1 << 62) + seq, poly_key, 32);

	poly1305_init(&ctx, poly_key);

	memset(aad, 0, 16);
	store_le64(aad, seq);
	aad[8] = tcp_flags;
	aad[9] = 0x01;
	poly1305_block(&ctx, aad, 0);

	if (prefix && prefix_len > 0) {
		for (i = 0; i + 16 <= prefix_len; i += 16)
			poly1305_block(&ctx, prefix + i, 1);

		n = prefix_len - i;
		if (n > 0) {
			memset(pad, 0, 16);
			memcpy(pad, prefix + i, n);
			pad[n] = 0x01;
			poly1305_block(&ctx, pad, 0);
		}
	}

	for (i = 0; i + 16 <= data_len; i += 16)
		poly1305_block(&ctx, data + i, 1);

	n = data_len - i;
	if (n > 0) {
		memset(pad, 0, 16);
		memcpy(pad, data + i, n);
		pad[n] = 0x01;
		poly1305_block(&ctx, pad, 0);
	}

	memset(pad, 0, 16);
	store_le64(pad, 9);
	store_le64(pad + 8, total_len);
	poly1305_block(&ctx, pad, 1);

	poly1305_finish(&ctx, full_tag);
	memcpy(tag, full_tag, TCPS_MAC_TAG_SIZE);

	memzero_explicit(poly_key, sizeof(poly_key));
	memzero_explicit(full_tag, sizeof(full_tag));
	memzero_explicit(&ctx, sizeof(ctx));
}

void tcps_compute_auth_tag(const uint8_t shared_static[TCPS_DH_SIZE],
			   const uint8_t client_dh[TCPS_DH_SIZE],
			   const uint8_t server_dh[TCPS_DH_SIZE],
			   uint32_t client_isn, uint32_t server_isn,
			   int is_client,
			   uint8_t tag[TCPS_AUTH_TAG_SIZE])
{
	uint8_t poly_key[32];
	uint8_t full_tag[16];
	uint8_t buf[16];
	struct poly1305_ctx ctx;
	size_t i;
	size_t n;

	memset(poly_key, 0, 32);
	chacha20_xor_stream(shared_static, (3ULL << 62), poly_key, 32);
	poly1305_init(&ctx, poly_key);

	memset(buf, 0, 16);
	store_le32(buf, client_isn);
	store_le32(buf + 4, server_isn);
	buf[8] = is_client ? 1 : 0;
	buf[9] = 0x01;
	poly1305_block(&ctx, buf, 0);

	for (i = 0; i + 16 <= TCPS_DH_SIZE; i += 16)
		poly1305_block(&ctx, client_dh + i, 1);
	n = TCPS_DH_SIZE - i;
	if (n > 0) {
		memset(buf, 0, 16);
		memcpy(buf, client_dh + i, n);
		buf[n] = 0x01;
		poly1305_block(&ctx, buf, 0);
	}

	for (i = 0; i + 16 <= TCPS_DH_SIZE; i += 16)
		poly1305_block(&ctx, server_dh + i, 1);
	n = TCPS_DH_SIZE - i;
	if (n > 0) {
		memset(buf, 0, 16);
		memcpy(buf, server_dh + i, n);
		buf[n] = 0x01;
		poly1305_block(&ctx, buf, 0);
	}

	memset(buf, 0, 16);
	store_le64(buf, 9);
	store_le64(buf + 8, (uint64_t)TCPS_DH_SIZE * 2);
	poly1305_block(&ctx, buf, 1);

	poly1305_finish(&ctx, full_tag);
	memcpy(tag, full_tag, TCPS_AUTH_TAG_SIZE);

	memzero_explicit(poly_key, sizeof(poly_key));
	memzero_explicit(full_tag, sizeof(full_tag));
	memzero_explicit(buf, sizeof(buf));
	memzero_explicit(&ctx, sizeof(ctx));
}
