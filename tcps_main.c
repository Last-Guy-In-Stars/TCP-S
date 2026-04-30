#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <net/checksum.h>
#include "tcps.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tcps");
MODULE_DESCRIPTION("Transparent TCP stream encryption via Curve25519 + ChaCha20");

static DEFINE_HASHTABLE(tcps_table, TCPS_HASH_BITS);
static DEFINE_SPINLOCK(tcps_lock);

struct tcps_conn *tcps_conn_find(__be32 saddr, __be16 sport,
                                 __be32 daddr, __be16 dport) {
    uint32_t h = saddr ^ daddr ^ sport ^ dport;
    struct tcps_conn *c;
    hash_for_each_possible_rcu(tcps_table, c, hnode, h) {
        if (c->saddr == saddr && c->daddr == daddr &&
            c->sport == sport && c->dport == dport)
            return c;
    }
    return NULL;
}

struct tcps_conn *tcps_conn_add(__be32 saddr, __be16 sport,
                                __be32 daddr, __be16 dport) {
    struct tcps_conn *c = kzalloc(sizeof(*c), GFP_ATOMIC);
    if (!c) return NULL;
    c->saddr = saddr; c->daddr = daddr;
    c->sport = sport; c->dport = dport;
    spin_lock_init(&c->lock);
    uint32_t h = saddr ^ daddr ^ sport ^ dport;
    spin_lock(&tcps_lock);
    hash_add_rcu(tcps_table, &c->hnode, h);
    spin_unlock(&tcps_lock);
    return c;
}

void tcps_conn_del(struct tcps_conn *c) {
    spin_lock(&tcps_lock);
    hash_del_rcu(&c->hnode);
    spin_unlock(&tcps_lock);
    kfree_rcu(c, rcu);
}

void tcps_conn_cleanup(void) {
    struct tcps_conn *c;
    struct hlist_node *tmp;
    unsigned bkt;
    hash_for_each_safe(tcps_table, bkt, tmp, c, hnode) {
        hash_del(&c->hnode);
        kfree(c);
    }
}

static int tcp_option_find_tcps(struct tcphdr *th) {
    int optlen = th->doff * 4 - sizeof(struct tcphdr);
    uint8_t *opt = (uint8_t *)th + sizeof(struct tcphdr);
    int i = 0;
    while (i < optlen) {
        if (opt[i] == 0) break;
        if (opt[i] == 1) { i++; continue; }
        if (i + 1 >= optlen) break;
        int len = opt[i + 1];
        if (len < 2) break;
        if (opt[i] == TCPS_OPT_KIND && len == TCPS_OPT_LEN &&
            opt[i + 2] == TCPS_OPT_MAGIC0 && opt[i + 3] == TCPS_OPT_MAGIC1)
            return 1;
        i += len;
    }
    return 0;
}

static int add_tcps_option(struct sk_buff *skb, struct tcphdr *th) {
    int opt_space = th->doff * 4 - sizeof(struct tcphdr);
    if (opt_space + TCPS_OPT_LEN > 40) return -ENOSPC;
    if (skb_ensure_writable(skb, skb->len)) return -ENOMEM;

    uint8_t *opt = (uint8_t *)th + sizeof(struct tcphdr) + opt_space;
    opt[0] = TCPS_OPT_KIND;
    opt[1] = TCPS_OPT_LEN;
    opt[2] = TCPS_OPT_MAGIC0;
    opt[3] = TCPS_OPT_MAGIC1;
    th->doff++;

    inet_proto_csum_replace2(&th->check, skb,
                             htons(opt_space), htons(opt_space + TCPS_OPT_LEN), 0);
    return 0;
}

static int do_handshake_init(struct tcps_conn *c) {
    get_random_bytes(c->my_priv, TCPS_PUBKEY_SIZE);
    c->my_priv[0] &= 248;
    c->my_priv[31] &= 127;
    c->my_priv[31] |= 64;
    curve25519_base(c->my_pub, c->my_priv);
    c->hs_sent_pub = 1;
    c->hs_bytes_sent = TCPS_PUBKEY_SIZE;
    c->state = TCPS_HANDSHAKE;
    return 0;
}

static void complete_handshake(struct tcps_conn *c) {
    uint8_t shared[TCPS_PUBKEY_SIZE];
    curve25519_shared(shared, c->my_priv, c->peer_pub);
    if (c->is_server)
        tcps_derive_keys(shared, c->dec_key, c->enc_key);
    else
        tcps_derive_keys(shared, c->enc_key, c->dec_key);
    memzero_explicit(shared, sizeof(shared));
    c->send_pos = 0;
    c->recv_pos = 0;
    c->state = TCPS_ENCRYPTED;
    pr_info("tcps: handshake complete %pI4:%u <-> %pI4:%u\n",
            &c->saddr, ntohs(c->sport), &c->daddr, ntohs(c->dport));
}

static unsigned int tcps_out(void *priv, struct sk_buff *skb,
                             const struct nf_hook_state *state) {
    if (!skb || skb->protocol != htons(ETH_P_IP)) return NF_ACCEPT;
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;
    if (skb_ensure_writable(skb, skb->len)) return NF_ACCEPT;
    struct tcphdr *th = tcp_hdr(skb);
    int tcplen = skb->len - iph->ihl * 4;

    if (th->syn && !th->ack) {
        add_tcps_option(skb, th);
        struct tcps_conn *c = tcps_conn_add(iph->saddr, th->source,
                                             iph->daddr, th->dest);
        if (c) { c->is_server = 0; c->state = TCPS_SYN_SEEN; c->isn_local = ntohl(th->seq); }
        return NF_ACCEPT;
    }

    if (th->syn && th->ack) {
        add_tcps_option(skb, th);
        return NF_ACCEPT;
    }

    struct tcps_conn *c = tcps_conn_find(iph->saddr, th->source, iph->daddr, th->dest);
    if (!c || c->state == TCPS_NONE) return NF_ACCEPT;

    int payload_off = th->doff * 4;
    int payload_len = tcplen - payload_off;
    if (payload_len <= 0) return NF_ACCEPT;

    uint8_t *payload = (uint8_t *)th + payload_off;

    spin_lock(&c->lock);

    if (c->state == TCPS_ESTABLISHED) {
        do_handshake_init(c);
    }

    if (c->state == TCPS_HANDSHAKE && c->hs_sent_pub) {
        spin_unlock(&c->lock);
        return NF_ACCEPT;
    }

    if (c->state == TCPS_ENCRYPTED) {
        chacha20_xor_stream(c->enc_key, c->send_pos, payload, payload_len);
        c->send_pos += payload_len;
        th->check = 0;
        th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       tcplen, IPPROTO_TCP,
                                       csum_partial(th, tcplen, 0));
        skb->ip_summed = CHECKSUM_NONE;
    }

    spin_unlock(&c->lock);
    return NF_ACCEPT;
}

static unsigned int tcps_in(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state) {
    if (!skb || skb->protocol != htons(ETH_P_IP)) return NF_ACCEPT;
    struct iphdr *iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;
    if (skb_ensure_writable(skb, skb->len)) return NF_ACCEPT;
    struct tcphdr *th = tcp_hdr(skb);
    int tcplen = skb->len - iph->ihl * 4;

    if (th->syn && th->ack) {
        if (tcp_option_find_tcps(th)) {
            struct tcps_conn *c = tcps_conn_find(iph->daddr, th->dest, iph->saddr, th->source);
            if (c) {
                c->is_server = 1;
                c->state = TCPS_ESTABLISHED;
                c->isn_remote = ntohl(th->seq);
            }
        }
        return NF_ACCEPT;
    }

    if (th->syn && !th->ack && tcp_option_find_tcps(th)) {
        return NF_ACCEPT;
    }

    struct tcps_conn *c = tcps_conn_find(iph->daddr, th->dest, iph->saddr, th->source);
    if (!c || c->state == TCPS_NONE) return NF_ACCEPT;

    int payload_off = th->doff * 4;
    int payload_len = tcplen - payload_off;
    if (payload_len <= 0) return NF_ACCEPT;

    uint8_t *payload = (uint8_t *)th + payload_off;

    spin_lock(&c->lock);

    if (c->state == TCPS_ESTABLISHED) {
        do_handshake_init(c);
    }

    if (c->state == TCPS_HANDSHAKE && !c->hs_recv_pub) {
        if (payload_len >= TCPS_PUBKEY_SIZE) {
            memcpy(c->peer_pub, payload, TCPS_PUBKEY_SIZE);
            c->hs_recv_pub = 1;
            c->hs_bytes_recv = TCPS_PUBKEY_SIZE;
            complete_handshake(c);
            payload += TCPS_PUBKEY_SIZE;
            payload_len -= TCPS_PUBKEY_SIZE;
        }
    }

    if (c->state == TCPS_ENCRYPTED && payload_len > 0) {
        chacha20_xor_stream(c->dec_key, c->recv_pos, payload, payload_len);
        c->recv_pos += payload_len;
        th->check = 0;
        th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
                                       tcplen, IPPROTO_TCP,
                                       csum_partial(th, tcplen, 0));
        skb->ip_summed = CHECKSUM_NONE;
    }

    spin_unlock(&c->lock);
    return NF_ACCEPT;
}

static struct nf_hook_ops tcps_ops[] = {
    {
        .hook     = tcps_out,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_LAST,
    },
    {
        .hook     = tcps_in,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_PRE_ROUTING,
        .priority = NF_IP_PRI_FIRST,
    },
};

static int __init tcps_init(void) {
    int err = nf_register_net_hooks(&init_net, tcps_ops, ARRAY_SIZE(tcps_ops));
    if (err) { pr_err("tcps: failed to register hooks\n"); return err; }
    pr_info("tcps: module loaded\n");
    return 0;
}

static void __exit tcps_exit(void) {
    nf_unregister_net_hooks(&init_net, tcps_ops, ARRAY_SIZE(tcps_ops));
    tcps_conn_cleanup();
    pr_info("tcps: module unloaded\n");
}

module_init(tcps_init);
module_exit(tcps_exit);
