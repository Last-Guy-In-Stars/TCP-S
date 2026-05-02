#ifndef TCPS_H
#define TCPS_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tcp.h>

#define TCPS_OPT_KIND   253
#define TCPS_OPT_LEN    36
#define TCPS_OPT_MAGIC0 'T'
#define TCPS_OPT_MAGIC1 'C'

#define TCPS_MAC_OPT_KIND   253
#define TCPS_MAC_OPT_LEN    12
#define TCPS_MAC_MAGIC0     'T'
#define TCPS_MAC_MAGIC1     'M'
#define TCPS_MAC_TAG_SIZE   8

#define TCPS_TI_OPT_KIND    253
#define TCPS_TI_OPT_LEN     40
#define TCPS_TI_MAGIC0      'T'
#define TCPS_TI_MAGIC1      'I'
#define TCPS_AUTH_TAG_SIZE  4

#define TCPS_KEY_SIZE   32
#define TCPS_DH_SIZE    32

#define TCPS_HASH_BITS  10
#define TCPS_PEER_HASH_BITS 8

#define TCPS_GC_INTERVAL   (30 * HZ)
#define TCPS_IDLE_TIMEOUT  (300 * HZ)
#define TCPS_DEAD_TIMEOUT  (60 * HZ)
#define TCPS_FIN_TIMEOUT   (120 * HZ)

enum tcps_state {
	TCPS_NONE = 0,
	TCPS_SYN_SENT,
	TCPS_SYN_RECV,
	TCPS_ENCRYPTED,
	TCPS_AUTHENTICATED,
	TCPS_DEAD,
};

struct tcps_conn {
	__be32 saddr, daddr;
	__be16 sport, dport;
	enum tcps_state state;
	int is_client;

	uint8_t enc_key[TCPS_KEY_SIZE];
	uint8_t dec_key[TCPS_KEY_SIZE];
	uint8_t mac_enc_key[TCPS_KEY_SIZE];
	uint8_t mac_dec_key[TCPS_KEY_SIZE];

	uint32_t client_isn;
	uint32_t server_isn;

	uint8_t dh_priv[TCPS_DH_SIZE];
	uint8_t dh_pub[TCPS_DH_SIZE];
	uint8_t dh_peer_pub[TCPS_DH_SIZE];

	uint8_t fin_out;
	uint8_t fin_in;
	uint8_t ti_sent;
	uint8_t ti_recv;
	unsigned long last_active;

	uint32_t send_wrap;
	uint32_t recv_wrap;
	uint64_t max_send_pos;
	uint64_t max_recv_pos;

	struct hlist_node hnode;
	struct rcu_head rcu;
	spinlock_t lock;
};

struct tcps_conn *tcps_conn_find_any(__be32 a1, __be16 p1,
				     __be32 a2, __be16 p2);
struct tcps_conn *tcps_conn_add(__be32 saddr, __be16 sport,
				__be32 daddr, __be16 dport);
void tcps_conn_cleanup(void);

void chacha20_xor_stream(const uint8_t key[32], uint64_t pos,
			 uint8_t *data, size_t len);
void tcps_dh_keygen(uint8_t priv[TCPS_DH_SIZE], uint8_t pub[TCPS_DH_SIZE]);
int tcps_dh_shared(const uint8_t priv[TCPS_DH_SIZE],
		   const uint8_t peer_pub[TCPS_DH_SIZE],
		   uint8_t shared[TCPS_DH_SIZE]);
void tcps_derive_session_keys(const uint8_t shared[TCPS_DH_SIZE],
			      uint32_t client_isn, uint32_t server_isn,
			      uint8_t key_c2s[TCPS_KEY_SIZE],
			      uint8_t key_s2c[TCPS_KEY_SIZE],
			      uint8_t mac_c2s[TCPS_KEY_SIZE],
			      uint8_t mac_s2c[TCPS_KEY_SIZE]);
void tcps_compute_mac(const uint8_t mac_key[TCPS_KEY_SIZE],
		      uint64_t seq, const uint8_t *data, size_t len,
		      uint8_t tag[TCPS_MAC_TAG_SIZE]);

struct tcps_peer_entry {
	__be32 addr;
	uint8_t pubkey[TCPS_DH_SIZE];
	struct hlist_node hnode;
	struct rcu_head rcu;
};

int tcps_tofu_verify(__be32 addr, const uint8_t pubkey[TCPS_DH_SIZE],
		     const uint8_t auth_tag[TCPS_AUTH_TAG_SIZE],
		     uint32_t client_isn, uint32_t server_isn,
		     int is_client);
void tcps_tofu_cleanup(void);

#endif
