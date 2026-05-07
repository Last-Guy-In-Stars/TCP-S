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
		memzero_explicit(blk, sizeof(blk));
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
		memzero_explicit(blk, sizeof(blk));
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
	size_t labellen = strlen(label);

	memset(input, 0, sizeof(input));
	if (labellen > 31)
		labellen = 31;
	memcpy(input, label, labellen);
	input[32] = counter;

	chacha20_xor_stream(prk, position, input, 64);
	memcpy(out, input, 32);
	memzero_explicit(input, sizeof(input));
}

void tcps_derive_keys(const uint8_t shared_secret[32], uint32_t client_isn,
		      uint32_t server_isn, int is_client,
		      uint8_t enc_key[32], uint8_t dec_key[32],
		      uint8_t mac_enc_key[32], uint8_t mac_dec_key[32])
{
	uint8_t prk[32];
	uint8_t c2s_key[32], s2c_key[32];
	uint8_t c2s_mac[32], s2c_mac[32];
	uint8_t extract_input[40];

	store_le32(extract_input, client_isn);
	store_le32(extract_input + 4, server_isn);
	memcpy(extract_input + 8, shared_secret, 32);

	chacha20_xor_stream(shared_secret, 0, extract_input, 40);
	memcpy(prk, extract_input, 32);

	kdf_expand(prk, (1ULL << 63), "TCPS c2s", 1, c2s_key);
	kdf_expand(prk, (1ULL << 63) | 64, "TCPS s2c", 2, s2c_key);
	kdf_expand(prk, (1ULL << 63) | 128, "TCPS cmac", 3, c2s_mac);
	kdf_expand(prk, (1ULL << 63) | 192, "TCPS smac", 4, s2c_mac);

	if (is_client) {
		memcpy(enc_key, c2s_key, 32);
		memcpy(dec_key, s2c_key, 32);
		memcpy(mac_enc_key, c2s_mac, 32);
		memcpy(mac_dec_key, s2c_mac, 32);
	} else {
		memcpy(enc_key, s2c_key, 32);
		memcpy(dec_key, c2s_key, 32);
		memcpy(mac_enc_key, s2c_mac, 32);
		memcpy(mac_dec_key, c2s_mac, 32);
	}

	memzero_explicit(prk, sizeof(prk));
	memzero_explicit(c2s_key, sizeof(c2s_key));
	memzero_explicit(s2c_key, sizeof(s2c_key));
	memzero_explicit(c2s_mac, sizeof(c2s_mac));
	memzero_explicit(s2c_mac, sizeof(s2c_mac));
	memzero_explicit(extract_input, sizeof(extract_input));
}

void tcps_derive_psk(const uint8_t dh_shared[32],
		     const uint8_t init_key_a[32],
		     const uint8_t init_key_b[32],
		     uint8_t psk[32])
{
	uint8_t input[128];

	memset(input, 0, sizeof(input));
	memcpy(input, "TCPS-PSK", 8);
	memcpy(input + 8, dh_shared, 32);
	memcpy(input + 40, init_key_a, 32);
	memcpy(input + 72, init_key_b, 32);

	chacha20_xor_stream(dh_shared, (1ULL << 62), input, 96);
	memcpy(psk, input, 32);

	memzero_explicit(input, sizeof(input));
}

void tcps_derive_psk_fallback(const uint8_t dh_shared[32], uint8_t psk[32])
{
	uint8_t input[32];

	memcpy(input, "TCPS-FB", 8);
	chacha20_xor_stream(dh_shared, (1ULL << 62) | (1ULL << 55), input, 32);
	memcpy(psk, input, 32);

	memzero_explicit(input, sizeof(input));
}

int tcps_dh_shared(const uint8_t my_private[32], const uint8_t peer_public[32],
		   uint8_t shared[32])
{
	int ret = curve25519(shared, my_private, peer_public);
	if (ret == 0) {
		int i;
		uint8_t z = 0;
		for (i = 0; i < 32; i++)
			z |= shared[i];
		if (z == 0)
			return -EINVAL;
	}
	return ret;
}

void tcps_gen_keypair(uint8_t private_key[32], uint8_t public_key[32])
{
	int tries = 0;
	curve25519_generate_secret(private_key);
	while (!curve25519_generate_public(public_key, private_key)) {
		curve25519_generate_secret(private_key);
		if (++tries > 16) {
			memset(private_key, 0, 32);
			memset(public_key, 0, 32);
			return;
		}
	}
}

struct poly1305_ctx {
	uint32_t r[5];
	uint32_t h[5];
	uint32_t s[4];
	uint8_t buf[16];
	uint32_t buflen;
};

static void poly1305_init(struct poly1305_ctx *ctx, const uint8_t key[32])
{
	uint32_t t0, t1, t2, t3;

	t0 = load_le32(key); t1 = load_le32(key + 4);
	t2 = load_le32(key + 8); t3 = load_le32(key + 12);

	t0 &= 0x0fffffff; t1 &= 0x0ffffffc;
	t2 &= 0x0ffffffc; t3 &= 0x0ffffffc;

	ctx->r[0] = t0 & 0x03ffffff;
	ctx->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
	ctx->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
	ctx->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
	ctx->r[4] = (t3 >> 8) & 0x03ffffff;

	ctx->s[0] = load_le32(key + 16);
	ctx->s[1] = load_le32(key + 20);
	ctx->s[2] = load_le32(key + 24);
	ctx->s[3] = load_le32(key + 28);

	memset(ctx->h, 0, sizeof(ctx->h));
	ctx->buflen = 0;
}

static void poly1305_blocks(struct poly1305_ctx *ctx, const uint8_t *in,
			    uint32_t len, uint32_t hibit)
{
	uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2];
	uint32_t r3 = ctx->r[3], r4 = ctx->r[4];
	uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
	uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2];
	uint32_t h3 = ctx->h[3], h4 = ctx->h[4];

	while (len >= 16) {
		uint32_t t0, t1, t2, t3;
		uint64_t d0, d1, d2, d3, d4, c;

		t0 = load_le32(in); t1 = load_le32(in + 4);
		t2 = load_le32(in + 8); t3 = load_le32(in + 12);

		h0 += t0 & 0x03ffffff;
		h1 += ((t0 >> 26) | (t1 << 6)) & 0x03ffffff;
		h2 += ((t1 >> 20) | (t2 << 12)) & 0x03ffffff;
		h3 += ((t2 >> 14) | (t3 << 18)) & 0x03ffffff;
		h4 += (t3 >> 8) | hibit;

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

		c = d0 >> 26; h0 = (uint32_t)d0 & 0x03ffffff;
		d1 += c; c = d1 >> 26; h1 = (uint32_t)d1 & 0x03ffffff;
		d2 += c; c = d2 >> 26; h2 = (uint32_t)d2 & 0x03ffffff;
		d3 += c; c = d3 >> 26; h3 = (uint32_t)d3 & 0x03ffffff;
		d4 += c; c = d4 >> 26; h4 = (uint32_t)d4 & 0x03ffffff;
		h0 += (uint32_t)c * 5;
		h1 += h0 >> 26; h0 &= 0x03ffffff;

		in += 16; len -= 16;
	}

	ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2;
	ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly1305_update(struct poly1305_ctx *ctx, const uint8_t *data,
			    uint32_t len)
{
	uint32_t i, want;

	if (ctx->buflen) {
		want = 16 - ctx->buflen;
		if (want > len) want = len;
		for (i = 0; i < want; i++)
			ctx->buf[ctx->buflen + i] = data[i];
		ctx->buflen += want;
		if (ctx->buflen < 16) return;
		poly1305_blocks(ctx, ctx->buf, 16, 1 << 24);
		ctx->buflen = 0;
		data += want; len -= want;
	}

	if (len >= 16) {
		uint32_t nb = len / 16;
		poly1305_blocks(ctx, data, nb * 16, 1 << 24);
		data += nb * 16; len -= nb * 16;
	}

	if (len) {
		for (i = 0; i < len; i++)
			ctx->buf[i] = data[i];
		ctx->buflen = len;
	}
}

static void poly1305_final(struct poly1305_ctx *ctx, uint8_t tag[16])
{
	uint32_t h0, h1, h2, h3, h4, g0, g1, g2, g3, g4, mask;
	uint64_t f;

	if (ctx->buflen) {
		uint8_t buf[16];
		memset(buf, 0, 16);
		memcpy(buf, ctx->buf, ctx->buflen);
		buf[ctx->buflen] = 1;
		poly1305_blocks(ctx, buf, 16, 0);
		memzero_explicit(buf, sizeof(buf));
	}

	h0 = ctx->h[0]; h1 = ctx->h[1]; h2 = ctx->h[2];
	h3 = ctx->h[3]; h4 = ctx->h[4];

	h1 += h0 >> 26; h0 &= 0x03ffffff;
	h2 += h1 >> 26; h1 &= 0x03ffffff;
	h3 += h2 >> 26; h2 &= 0x03ffffff;
	h4 += h3 >> 26; h3 &= 0x03ffffff;
	h0 += (h4 >> 24) * 5; h4 &= 0x00ffffff;
	h1 += h0 >> 26; h0 &= 0x03ffffff;

	g0 = h0 + 5; g1 = h1 + (g0 >> 26); g0 &= 0x03ffffff;
	g2 = h2 + (g1 >> 26); g1 &= 0x03ffffff;
	g3 = h3 + (g2 >> 26); g2 &= 0x03ffffff;
	g4 = h4 + (g3 >> 26) - (1 << 24); g3 &= 0x03ffffff;

	mask = (uint32_t)((int32_t)g4 >> 31);

	h0 = (h0 & ~mask) | (g0 & mask);
	h1 = (h1 & ~mask) | (g1 & mask);
	h2 = (h2 & ~mask) | (g2 & mask);
	h3 = (h3 & ~mask) | (g3 & mask);

	f = (uint64_t)h0 + ctx->s[0]; h0 = (uint32_t)f;
	f = (uint64_t)h1 + ctx->s[1] + (f >> 32); h1 = (uint32_t)f;
	f = (uint64_t)h2 + ctx->s[2] + (f >> 32); h2 = (uint32_t)f;
	f = (uint64_t)h3 + ctx->s[3] + (f >> 32); h3 = (uint32_t)f;

	store_le32(tag, h0);
	store_le32(tag + 4, h1);
	store_le32(tag + 8, h2);
	store_le32(tag + 12, h3);

	memzero_explicit(ctx, sizeof(*ctx));
}

void tcps_compute_mac(const uint8_t mac_key[32], uint64_t pos,
		      const uint8_t *aad, uint32_t aad_len,
		      const uint8_t *payload, uint32_t payload_len,
		      uint8_t tag[TCPS_TAG_SIZE])
{
	uint8_t otp_key[32];
	struct poly1305_ctx ctx;
	uint8_t pad[16];
	uint8_t len_buf[16];
	uint32_t aad_padded, pay_padded;

	memset(otp_key, 0, 32);
	chacha20_xor_stream(mac_key, pos + 32, otp_key, 32);
	poly1305_init(&ctx, otp_key);

	if (aad_len > 0) {
		poly1305_update(&ctx, aad, aad_len);
		aad_padded = (aad_len + 15) & ~15u;
		if (aad_padded > aad_len) {
			memset(pad, 0, 16);
			poly1305_update(&ctx, pad, aad_padded - aad_len);
		}
	}

	if (payload_len > 0) {
		poly1305_update(&ctx, payload, payload_len);
		pay_padded = (payload_len + 15) & ~15u;
		if (pay_padded > payload_len) {
			memset(pad, 0, 16);
			poly1305_update(&ctx, pad, pay_padded - payload_len);
		}
	}

	memset(len_buf, 0, 16);
	store_le32(len_buf, aad_len);
	store_le32(len_buf + 4, 0);
	store_le32(len_buf + 8, payload_len);
	store_le32(len_buf + 12, 0);
	poly1305_update(&ctx, len_buf, 16);

	poly1305_final(&ctx, tag);
	memzero_explicit(otp_key, sizeof(otp_key));
	memzero_explicit(pad, sizeof(pad));
	memzero_explicit(len_buf, sizeof(len_buf));
}
