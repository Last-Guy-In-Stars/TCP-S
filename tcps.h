#ifndef TCPS_H
#define TCPS_H

#include <linux/types.h>

#define TCPS_KEY_SIZE		32
#define TCPS_PSK_SIZE		32

#define TCPS_HASH_BITS		10
#define TCPS_PEER_HASH_BITS	6

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

	uint32_t client_isn, server_isn;
	int is_client;
	int fin_in, fin_out;
	int kill;
	int keys_derived;

	unsigned long last_active;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

struct tcps_peer {
	__be32 addr;
	uint8_t public_key[32];
	unsigned long first_seen;
	struct hlist_node hnode;
	struct rcu_head rcu;
};

void chacha20_xor_stream(const uint8_t key[32], uint64_t pos,
			 uint8_t *data, uint32_t len);
void tcps_derive_keys(const uint8_t shared_secret[32], uint32_t client_isn,
		      uint32_t server_isn, int is_client,
		      uint8_t enc_key[32], uint8_t dec_key[32]);

int tcps_dh_shared(const uint8_t my_private[32], const uint8_t peer_public[32],
		   uint8_t shared[32]);
void tcps_gen_keypair(uint8_t private_key[32], uint8_t public_key[32]);

#endif
