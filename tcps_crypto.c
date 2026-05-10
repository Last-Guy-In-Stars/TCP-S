#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/module.h>
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

typedef int64_t limb;
typedef limb fe[5];

#define MASK51 ((limb)0x7FFFFFFFFFFFF)

static void fe_load(fe h, const uint8_t s[32])
{
	uint64_t x;

	x = (uint64_t)s[0] | ((uint64_t)s[1] << 8) |
	    ((uint64_t)s[2] << 16) | ((uint64_t)s[3] << 24) |
	    ((uint64_t)s[4] << 32) | ((uint64_t)s[5] << 40) |
	    ((uint64_t)s[6] << 48) | ((uint64_t)s[7] << 56);
	h[0] = x & MASK51;

	x = (uint64_t)s[6] | ((uint64_t)s[7] << 8) |
	    ((uint64_t)s[8] << 16) | ((uint64_t)s[9] << 24) |
	    ((uint64_t)s[10] << 32) | ((uint64_t)s[11] << 40) |
	    ((uint64_t)s[12] << 48) | ((uint64_t)s[13] << 56);
	h[1] = (x >> 3) & MASK51;

	x = (uint64_t)s[12] | ((uint64_t)s[13] << 8) |
	    ((uint64_t)s[14] << 16) | ((uint64_t)s[15] << 24) |
	    ((uint64_t)s[16] << 32) | ((uint64_t)s[17] << 40) |
	    ((uint64_t)s[18] << 48) | ((uint64_t)s[19] << 56);
	h[2] = (x >> 6) & MASK51;

	x = (uint64_t)s[19] | ((uint64_t)s[20] << 8) |
	    ((uint64_t)s[21] << 16) | ((uint64_t)s[22] << 24) |
	    ((uint64_t)s[23] << 32) | ((uint64_t)s[24] << 40) |
	    ((uint64_t)s[25] << 48) | ((uint64_t)s[26] << 56);
	h[3] = (x >> 1) & MASK51;

	x = (uint64_t)s[24] | ((uint64_t)s[25] << 8) |
	    ((uint64_t)s[26] << 16) | ((uint64_t)s[27] << 24) |
	    ((uint64_t)s[28] << 32) | ((uint64_t)s[29] << 40) |
	    ((uint64_t)s[30] << 48) | ((uint64_t)s[31] << 56);
	h[4] = (x >> 12) & MASK51;
}

static void fe_store(uint8_t s[32], const fe h)
{
	limb t[5];
	limb c;
	uint64_t v;

	memcpy(t, h, 40);

	c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
	c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
	c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
	c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
	c = t[4] >> 51; t[4] &= MASK51; t[0] += c * 19;

	c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
	c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
	c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
	c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
	c = t[4] >> 51; t[4] &= MASK51; t[0] += c * 19;

	t[0] += 19;

	c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
	c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
	c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
	c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
	c = t[4] >> 51; t[4] &= MASK51; t[0] += c * 19;

	t[0] += ((limb)1 << 51) - 19;
	t[1] += ((limb)1 << 51) - 1;
	t[2] += ((limb)1 << 51) - 1;
	t[3] += ((limb)1 << 51) - 1;
	t[4] += ((limb)1 << 51) - 1;

	c = t[0] >> 51; t[0] &= MASK51; t[1] += c;
	c = t[1] >> 51; t[1] &= MASK51; t[2] += c;
	c = t[2] >> 51; t[2] &= MASK51; t[3] += c;
	c = t[3] >> 51; t[3] &= MASK51; t[4] += c;
	t[4] &= MASK51;

	v = (uint64_t)t[0] | ((uint64_t)t[1] << 51);
	s[0] = (uint8_t)(v); s[1] = (uint8_t)(v >> 8);
	s[2] = (uint8_t)(v >> 16); s[3] = (uint8_t)(v >> 24);
	s[4] = (uint8_t)(v >> 32); s[5] = (uint8_t)(v >> 40);
	s[6] = (uint8_t)(v >> 48); s[7] = (uint8_t)(v >> 56);

	v = ((uint64_t)t[1] >> 13) | ((uint64_t)t[2] << 38);
	s[8] = (uint8_t)(v); s[9] = (uint8_t)(v >> 8);
	s[10] = (uint8_t)(v >> 16); s[11] = (uint8_t)(v >> 24);
	s[12] = (uint8_t)(v >> 32); s[13] = (uint8_t)(v >> 40);
	s[14] = (uint8_t)(v >> 48); s[15] = (uint8_t)(v >> 56);

	v = ((uint64_t)t[2] >> 26) | ((uint64_t)t[3] << 25);
	s[16] = (uint8_t)(v); s[17] = (uint8_t)(v >> 8);
	s[18] = (uint8_t)(v >> 16); s[19] = (uint8_t)(v >> 24);
	s[20] = (uint8_t)(v >> 32); s[21] = (uint8_t)(v >> 40);
	s[22] = (uint8_t)(v >> 48); s[23] = (uint8_t)(v >> 56);

	v = ((uint64_t)t[3] >> 39) | ((uint64_t)t[4] << 12);
	s[24] = (uint8_t)(v); s[25] = (uint8_t)(v >> 8);
	s[26] = (uint8_t)(v >> 16); s[27] = (uint8_t)(v >> 24);
	s[28] = (uint8_t)(v >> 32); s[29] = (uint8_t)(v >> 40);
	s[30] = (uint8_t)(v >> 48); s[31] = (uint8_t)(v >> 56);

	memzero_explicit(t, sizeof(t));
}

static void fe_add(fe out, const fe a, const fe b)
{
	int i;
	for (i = 0; i < 5; i++)
		out[i] = a[i] + b[i];
}

static void fe_sub(fe out, const fe a, const fe b)
{
	int i;
	for (i = 0; i < 5; i++)
		out[i] = a[i] - b[i];
}

static void fe_mul(fe out, const fe a, const fe b)
{
	__int128 h0, h1, h2, h3, h4;
	limb f0 = a[0], f1 = a[1], f2 = a[2], f3 = a[3], f4 = a[4];
	limb g0 = b[0], g1 = b[1], g2 = b[2], g3 = b[3], g4 = b[4];

	h0 = (__int128)f0*g0 + 19*((__int128)f1*g4 + (__int128)f2*g3 + (__int128)f3*g2 + (__int128)f4*g1);
	h1 = (__int128)f0*g1 + (__int128)f1*g0 + 19*((__int128)f2*g4 + (__int128)f3*g3 + (__int128)f4*g2);
	h2 = (__int128)f0*g2 + (__int128)f1*g1 + (__int128)f2*g0 + 19*((__int128)f3*g4 + (__int128)f4*g3);
	h3 = (__int128)f0*g3 + (__int128)f1*g2 + (__int128)f2*g1 + (__int128)f3*g0 + 19*(__int128)f4*g4;
	h4 = (__int128)f0*g4 + (__int128)f1*g3 + (__int128)f2*g2 + (__int128)f3*g1 + (__int128)f4*g0;

	h1 += h0 >> 51; h0 -= (h0 >> 51) << 51;
	h2 += h1 >> 51; h1 -= (h1 >> 51) << 51;
	h3 += h2 >> 51; h2 -= (h2 >> 51) << 51;
	h4 += h3 >> 51; h3 -= (h3 >> 51) << 51;
	h0 += (h4 >> 51) * 19; h4 -= (h4 >> 51) << 51;
	h1 += h0 >> 51; h0 -= (h0 >> 51) << 51;

	out[0] = (limb)h0; out[1] = (limb)h1; out[2] = (limb)h2;
	out[3] = (limb)h3; out[4] = (limb)h4;
}

static void fe_sq(fe out, const fe a)
{
	fe_mul(out, a, a);
}

static void fe_mul121666(fe out, const fe a)
{
	fe k = { 121666, 0, 0, 0, 0 };
	fe_mul(out, a, k);
}

static void fe_sq_n(fe out, const fe in, int n)
{
	int i;
	fe_sq(out, in);
	for (i = 1; i < n; i++)
		fe_sq(out, out);
}

static void fe_inv(fe out, const fe z)
{
	fe a, t0, b, c;

	fe_sq(a, z);
	fe_sq_n(t0, a, 2);
	fe_mul(b, t0, z);
	fe_mul(a, b, a);
	fe_sq(t0, a);
	fe_mul(b, t0, b);
	fe_sq_n(t0, b, 5);
	fe_mul(b, t0, b);
	fe_sq_n(t0, b, 10);
	fe_mul(c, t0, b);
	fe_sq_n(t0, c, 20);
	fe_mul(t0, t0, c);
	fe_sq_n(t0, t0, 10);
	fe_mul(b, t0, b);
	fe_sq_n(t0, b, 50);
	fe_mul(c, t0, b);
	fe_sq_n(t0, c, 100);
	fe_mul(t0, t0, c);
	fe_sq_n(t0, t0, 50);
	fe_mul(t0, t0, b);
	fe_sq_n(t0, t0, 5);
	fe_mul(out, t0, a);

	memzero_explicit(a, sizeof(a));
	memzero_explicit(t0, sizeof(t0));
	memzero_explicit(b, sizeof(b));
	memzero_explicit(c, sizeof(c));
}

static void fe_cswap(fe a, fe b, limb swap)
{
	limb mask = -swap;
	int i;
	for (i = 0; i < 5; i++) {
		limb t = mask & (a[i] ^ b[i]);
		a[i] ^= t;
		b[i] ^= t;
	}
}

static const uint8_t curve25519_base[32] = { 9 };

static void curve25519_scalar(uint8_t out[32], const uint8_t scalar[32],
			      const uint8_t point[32])
{
	fe x1, x2, z2, x3, z3;
	fe A, B, C, D, DA, CB, AA, BB, E;
	uint8_t e[32];
	limb s;
	int i;

	memcpy(e, scalar, 32);
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	fe_load(x1, point);
	x2[0] = 1; x2[1] = 0; x2[2] = 0; x2[3] = 0; x2[4] = 0;
	z2[0] = 0; z2[1] = 0; z2[2] = 0; z2[3] = 0; z2[4] = 0;
	memcpy(x3, x1, 40);
	z3[0] = 1; z3[1] = 0; z3[2] = 0; z3[3] = 0; z3[4] = 0;

	for (i = 254; i >= 0; i--) {
		s = (e[i >> 3] >> (i & 7)) & 1;
		fe_cswap(x2, x3, s);
		fe_cswap(z2, z3, s);

		fe_add(A, x2, z2);
		fe_sub(B, x2, z2);
		fe_add(C, x3, z3);
		fe_sub(D, x3, z3);

		fe_mul(DA, D, A);
		fe_mul(CB, C, B);

		fe_add(x3, DA, CB);
		fe_sq(x3, x3);
		fe_sub(z3, DA, CB);
		fe_sq(z3, z3);
		fe_mul(z3, z3, x1);

		fe_sq(AA, A);
		fe_sq(BB, B);
		fe_mul(x2, AA, BB);

		fe_sub(E, AA, BB);
		fe_mul121666(z2, E);
		fe_add(z2, z2, AA);
		fe_mul(z2, z2, E);

		fe_cswap(x2, x3, s);
		fe_cswap(z2, z3, s);
	}

	fe_inv(z3, z2);
	fe_mul(x2, x2, z3);
	fe_store(out, x2);

	memzero_explicit(x1, sizeof(x1));
	memzero_explicit(x2, sizeof(x2));
	memzero_explicit(z2, sizeof(z2));
	memzero_explicit(x3, sizeof(x3));
	memzero_explicit(z3, sizeof(z3));
	memzero_explicit(A, sizeof(A));
	memzero_explicit(B, sizeof(B));
	memzero_explicit(C, sizeof(C));
	memzero_explicit(D, sizeof(D));
	memzero_explicit(DA, sizeof(DA));
	memzero_explicit(CB, sizeof(CB));
	memzero_explicit(AA, sizeof(AA));
	memzero_explicit(BB, sizeof(BB));
	memzero_explicit(E, sizeof(E));
	memzero_explicit(e, sizeof(e));
}

int tcps_dh_shared(const uint8_t my_private[32], const uint8_t peer_public[32],
		   uint8_t shared[32])
{
	int i;
	uint8_t z = 0;

	curve25519_scalar(shared, my_private, peer_public);
	for (i = 0; i < 32; i++)
		z |= shared[i];
	if (z == 0)
		return -EINVAL;
	return 0;
}

void tcps_gen_keypair(uint8_t private_key[32], uint8_t public_key[32])
{
	get_random_bytes(private_key, 32);
	private_key[0] &= 248;
	private_key[31] &= 127;
	private_key[31] |= 64;
	curve25519_scalar(public_key, private_key, curve25519_base);
}

int tcps_derive_public(const uint8_t private_key[32], uint8_t public_key[32])
{
	uint8_t clamped[32];
	int i;
	uint8_t z = 0;

	memcpy(clamped, private_key, 32);
	clamped[0] &= 248;
	clamped[31] &= 127;
	clamped[31] |= 64;
	curve25519_scalar(public_key, clamped, curve25519_base);
	memzero_explicit(clamped, sizeof(clamped));

	for (i = 0; i < 32; i++)
		z |= public_key[i];
	if (z == 0)
		return -EINVAL;
	return 0;
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
