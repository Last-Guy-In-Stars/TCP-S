#ifndef TCPS_H
#define TCPS_H

#include <linux/types.h>

#define TCPS_KEY_SIZE		32
#define TCPS_PSK_SIZE		32
#define TCPS_INIT_KEY_SIZE	32
#define TCPS_TAG_SIZE		16
#define TCPS_MAC_SIZE		4

#define TCPS_HASH_BITS		10
#define TCPS_PEER_HASH_BITS	6
#define TCPS_MAX_PEERS		64

enum tcps_state {
	TCPS_NONE = 0,
	TCPS_PROBE_SYN,
	TCPS_PROBE_SYNACK,
	TCPS_KEYED,
	TCPS_DEAD,
};

struct tcps_conn {
	__be32 saddr, daddr;
	__be16 sport, dport;
	enum tcps_state state;
	spinlock_t lock;

	uint8_t enc_key[TCPS_KEY_SIZE];
	uint8_t dec_key[TCPS_KEY_SIZE];
	uint8_t mac_enc_key[TCPS_KEY_SIZE];
	uint8_t mac_dec_key[TCPS_KEY_SIZE];

	uint32_t client_isn, server_isn;
	uint32_t enc_seq_hi, dec_seq_hi;
	int is_client;
	int fin_in, fin_out;
	int kill;
	int keys_derived;
	int gso_disabled;
	int peer_has_mac;

	unsigned long last_active;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

struct tcps_peer {
	__be32 addr;
	uint8_t public_key[32];
	uint8_t psk[TCPS_PSK_SIZE];
	uint8_t prev_psk[TCPS_PSK_SIZE];
	uint8_t psk_fingerprint[8];
	int psk_ready;
	int psk_verified;
	int has_prev_psk;
	unsigned long first_seen;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

#define TCPS_SKB_MARK		0x54435053

#define TCPS_DISC_TYPE_DISCOVER		0x01
#define TCPS_DISC_TYPE_KEYXCHG		0x02
#define TCPS_DISC_TYPE_KEYXCHG_AUTH	0x03

#define TCPS_KEY_ROTATE_INTERVAL	3600

void chacha20_xor_stream(const uint8_t key[32], uint64_t pos,
			 uint8_t *data, uint32_t len);
void tcps_derive_keys(const uint8_t psk[32], uint32_t client_isn,
		      uint32_t server_isn, int is_client,
		      uint8_t enc_key[32], uint8_t dec_key[32],
		      uint8_t mac_enc_key[32], uint8_t mac_dec_key[32]);
void tcps_derive_psk(const uint8_t dh_shared[32],
		     const uint8_t init_key_a[32],
		     const uint8_t init_key_b[32],
		     uint8_t psk[32]);
void tcps_derive_psk_fallback(const uint8_t dh_shared[32], uint8_t psk[32]);

int tcps_dh_shared(const uint8_t my_private[32], const uint8_t peer_public[32],
		   uint8_t shared[32]);
void tcps_gen_keypair(uint8_t private_key[32], uint8_t public_key[32]);

void tcps_compute_mac(const uint8_t mac_key[32], uint64_t pos,
		      const uint8_t *aad, uint32_t aad_len,
		      const uint8_t *payload, uint32_t payload_len,
		      uint8_t tag[TCPS_TAG_SIZE]);

static inline int tcps_ct_memcmp(const void *a, const void *b, size_t len)
{
	const uint8_t *xa = a, *xb = b;
	size_t i;
	uint8_t r = 0;
	for (i = 0; i < len; i++)
		r |= xa[i] ^ xb[i];
	return r;
}

#endif
