#ifndef TCPS_H
#define TCPS_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tcp.h>

#define TCPS_OPT_KIND  253
#define TCPS_OPT_LEN   4
#define TCPS_OPT_MAGIC0 'T'
#define TCPS_OPT_MAGIC1 'C'

#define TCPS_PUBKEY_SIZE 32
#define TCPS_KEY_SIZE    32

#define TCPS_HASH_BITS 10
#define TCPS_MAX_CONNS (1 << TCPS_HASH_BITS)

enum tcps_state {
    TCPS_NONE = 0,
    TCPS_SYN_SEEN,
    TCPS_ESTABLISHED,
    TCPS_HANDSHAKE,
    TCPS_ENCRYPTED,
    TCPS_DEAD,
};

struct tcps_conn {
    __be32 saddr, daddr;
    __be16 sport, dport;
    enum tcps_state state;
    int is_server;

    uint8_t my_priv[TCPS_PUBKEY_SIZE];
    uint8_t my_pub[TCPS_PUBKEY_SIZE];
    uint8_t peer_pub[TCPS_PUBKEY_SIZE];

    uint8_t enc_key[TCPS_KEY_SIZE];
    uint8_t dec_key[TCPS_KEY_SIZE];

    uint64_t send_pos;
    uint64_t recv_pos;

    uint32_t isn_local;
    uint32_t isn_remote;
    uint32_t hs_bytes_sent;
    uint32_t hs_bytes_recv;
    int hs_sent_pub;
    int hs_recv_pub;

    struct hlist_node hnode;
    struct rcu_head rcu;
    spinlock_t lock;
};

struct tcps_conn *tcps_conn_find(__be32 saddr, __be16 sport,
                                 __be32 daddr, __be16 dport);
struct tcps_conn *tcps_conn_add(__be32 saddr, __be16 sport,
                                __be32 daddr, __be16 dport);
void tcps_conn_del(struct tcps_conn *c);
void tcps_conn_cleanup(void);

void curve25519_base(uint8_t pub[32], const uint8_t priv[32]);
void curve25519_shared(uint8_t out[32], const uint8_t priv[32], const uint8_t pub[32]);
void chacha20_xor_stream(const uint8_t key[32], uint64_t pos,
                          uint8_t *data, size_t len);
void tcps_derive_keys(const uint8_t shared[32],
                      uint8_t key_out[32], uint8_t key_in[32]);

#endif
