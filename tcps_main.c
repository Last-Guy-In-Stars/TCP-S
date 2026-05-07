#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/workqueue.h>
#include <linux/inet.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sockptr.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/sock.h>
#include <crypto/curve25519.h>
#include "tcps.h"

MODULE_LICENSE("MIT");
MODULE_AUTHOR("ArtamonovKA (GLM-5.1)");
MODULE_DESCRIPTION("Transparent TCP encryption: X25519 init-key exchange + ChaCha20-Poly1305 + PSK + forward secrecy + TOFU unicast discovery");

#define TCPS_MAX_SKIP_PORTS 8
static int tcps_skip_ports[TCPS_MAX_SKIP_PORTS] = { 22 };
static int tcps_skip_count = 1;
module_param_array_named(skip_ports, tcps_skip_ports, int, &tcps_skip_count, 0644);
MODULE_PARM_DESC(skip_ports, "Ports to skip (already encrypted, e.g. 22 443)");

static int tcps_strict_tofu;
module_param_named(strict_tofu, tcps_strict_tofu, int, 0644);
MODULE_PARM_DESC(strict_tofu, "1=reject key changes (block MITM); 0=accept with warning (default)");

static int tcps_psk_require_verify;
module_param_named(psk_require_verify, tcps_psk_require_verify, int, 0644);
MODULE_PARM_DESC(psk_require_verify, "1=require manual verify before full PSK; 0=auto-trust (default)");

static int tcps_rotate_interval = TCPS_KEY_ROTATE_INTERVAL;
module_param_named(rotate_interval, tcps_rotate_interval, int, 0644);
MODULE_PARM_DESC(rotate_interval, "Key rotation interval in seconds (default 3600)");

static int tcps_should_skip(__be16 port)
{
	int i;
	for (i = 0; i < READ_ONCE(tcps_skip_count) && i < TCPS_MAX_SKIP_PORTS; i++)
		if (ntohs(port) == READ_ONCE(tcps_skip_ports[i]))
			return 1;
	return 0;
}

static uint8_t tcps_my_init_key[CURVE25519_KEY_SIZE];
static uint8_t tcps_my_public[CURVE25519_KEY_SIZE];
static uint8_t tcps_prev_init_key[CURVE25519_KEY_SIZE];
static int tcps_has_prev_init;

static DEFINE_HASHTABLE(tcps_table, TCPS_HASH_BITS);
static DEFINE_SPINLOCK(tcps_lock);

static DEFINE_HASHTABLE(tcps_peers, TCPS_PEER_HASH_BITS);
static DEFINE_SPINLOCK(tcps_peers_lock);
static int tcps_peer_count;

#define TCPS_OPT_KIND	253
#define TCPS_OPT_LEN	4
#define TCPS_OPT_MAGIC	0x5443

#define TCPS_TM_OPT_KIND	253
#define TCPS_TM_OPT_LEN		8
#define TCPS_TM_OPT_MAGIC	0x544D

#define TCPS_DISC_PORT	54321
#define TCPS_DISC_MAGIC	0x54435053

struct tcps_disc_pkt {
	__be32 magic;
	uint8_t type;
	uint8_t pubkey[CURVE25519_KEY_SIZE];
	uint8_t enc_init[CURVE25519_KEY_SIZE];
	uint8_t auth_tag[TCPS_MAC_SIZE];
};

static struct socket *tcps_disc_sock;
static struct task_struct *tcps_disc_task;

static struct tcps_peer *tcps_peer_lookup(__be32 addr)
{
	struct tcps_peer *p;
	uint32_t h = jhash_1word((__force u32)addr, 0);
	hash_for_each_possible_rcu(tcps_peers, p, hnode, h) {
		if (p->addr == addr)
			return p;
	}
	return NULL;
}

static void tcps_peer_free_rcu(struct rcu_head *rh)
{
	struct tcps_peer *p = container_of(rh, struct tcps_peer, rcu);
	memzero_explicit(p->psk, sizeof(p->psk));
	memzero_explicit(p->prev_psk, sizeof(p->prev_psk));
	kfree(p);
}

static int tcps_peer_add(__be32 addr, const uint8_t public_key[32])
{
	struct tcps_peer *p, *old;
	uint32_t h;

	rcu_read_lock();
	old = tcps_peer_lookup(addr);
	if (old) {
		if (memcmp(old->public_key, public_key, 32) == 0) {
			rcu_read_unlock();
			return 0;
		}
		if (tcps_strict_tofu) {
			rcu_read_unlock();
			pr_alert("tcps: STRICT TOFU: key change BLOCKED for %pI4\n",
				 &addr);
			return -EPERM;
		}
		pr_warn("tcps: TOFU key change for %pI4 (updating)\n", &addr);
		spin_lock(&tcps_peers_lock);
		memcpy(old->public_key, public_key, 32);
		old->psk_ready = 0;
		old->first_seen = jiffies;
		spin_unlock(&tcps_peers_lock);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();

	if (tcps_peer_count >= TCPS_MAX_PEERS)
		return -ENOMEM;

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return -ENOMEM;

	p->addr = addr;
	memcpy(p->public_key, public_key, 32);
	p->psk_ready = 0;
	p->has_prev_psk = 0;
	p->first_seen = jiffies;

	h = jhash_1word((__force u32)addr, 0);
	spin_lock(&tcps_peers_lock);
	if (tcps_peer_count >= TCPS_MAX_PEERS) {
		spin_unlock(&tcps_peers_lock);
		kfree(p);
		return -ENOMEM;
	}
	hash_add_rcu(tcps_peers, &p->hnode, h);
	tcps_peer_count++;
	spin_unlock(&tcps_peers_lock);

	pr_info("tcps: TOFU added peer %pI4\n", &addr);
	return 0;
}

static void tcps_peer_set_psk(__be32 addr, const uint8_t psk[32])
{
	struct tcps_peer *p;

	rcu_read_lock();
	p = tcps_peer_lookup(addr);
	if (p) {
		spin_lock(&tcps_peers_lock);
		if (p->psk_ready) {
			memcpy(p->prev_psk, p->psk, 32);
			p->has_prev_psk = 1;
		}
		memcpy(p->psk, psk, 32);
		memcpy(p->psk_fingerprint, psk, 8);
		p->psk_ready = 1;
		p->psk_verified = 0;
		spin_unlock(&tcps_peers_lock);
	}
	rcu_read_unlock();
}

static int tcps_peer_get_prev_psk(__be32 addr, uint8_t prev_psk[32])
{
	struct tcps_peer *p;

	rcu_read_lock();
	p = tcps_peer_lookup(addr);
	if (p && p->has_prev_psk) {
		spin_lock(&tcps_peers_lock);
		memcpy(prev_psk, p->prev_psk, 32);
		spin_unlock(&tcps_peers_lock);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	return -ENOENT;
}

static int tcps_peer_verify_psk(__be32 addr, const uint8_t fingerprint[8])
{
	struct tcps_peer *p;

	rcu_read_lock();
	p = tcps_peer_lookup(addr);
	if (!p) {
		rcu_read_unlock();
		return -ENOENT;
	}
	spin_lock(&tcps_peers_lock);
	if (!p->psk_ready) {
		spin_unlock(&tcps_peers_lock);
		rcu_read_unlock();
		return -ENOENT;
	}
	if (memcmp(p->psk_fingerprint, fingerprint, 8) != 0) {
		spin_unlock(&tcps_peers_lock);
		rcu_read_unlock();
		return -EINVAL;
	}
	p->psk_verified = 1;
	spin_unlock(&tcps_peers_lock);
	rcu_read_unlock();
	pr_info("tcps: PSK VERIFIED for %pI4\n", &addr);
	return 0;
}

static int tcps_peer_get_psk(__be32 addr, uint8_t psk[32])
{
	struct tcps_peer *p;

	rcu_read_lock();
	p = tcps_peer_lookup(addr);
	if (p && p->psk_ready) {
		if (tcps_psk_require_verify && !p->psk_verified) {
			rcu_read_unlock();
			return -EPERM;
		}
		spin_lock(&tcps_peers_lock);
		memcpy(psk, p->psk, 32);
		spin_unlock(&tcps_peers_lock);
		rcu_read_unlock();
		return 0;
	}
	rcu_read_unlock();
	return -ENOENT;
}

static void tcps_recalc_csum(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

	if (tcplen < (int)sizeof(struct tcphdr))
		return;

	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	th->check = 0;
	th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				      tcplen, IPPROTO_TCP,
				      csum_partial(th, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE;
}

static void tcps_trigger_discover(__be32 peer_addr);

static int tcps_opt_end(const struct tcphdr *th, int tcplen)
{
	return min(tcplen, (int)th->doff * 4);
}

static int tcps_has_probe(const struct tcphdr *th, int tcplen)
{
	int off = sizeof(*th);
	int end = tcps_opt_end(th, tcplen);
	const uint8_t *opt = (const uint8_t *)th;

	while (off + 1 < end) {
		if (opt[off] == 0)
			return 0;
		if (opt[off] == 1) {
			off++;
			continue;
		}
		if (off + opt[off + 1] > end || opt[off + 1] < 2)
			return 0;
		if (opt[off] == TCPS_OPT_KIND && opt[off + 1] == TCPS_OPT_LEN) {
			uint16_t magic = (uint16_t)opt[off + 2] << 8 |
					 (uint16_t)opt[off + 3];
			if (magic == TCPS_OPT_MAGIC)
				return 1;
		}
		off += opt[off + 1];
	}
	return 0;
}

static int tcps_add_probe(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int old_doff = th->doff * 4;
	int total = TCPS_OPT_LEN;
	uint8_t *opt;

	if (old_doff + total > 60)
		return 0;

	if (skb_tailroom(skb) < total) {
		if (pskb_expand_head(skb, 0, total - skb_tailroom(skb),
				     GFP_ATOMIC))
			return 0;
		iph = ip_hdr(skb);
		th = tcp_hdr(skb);
	}

	opt = (uint8_t *)th + old_doff;
	opt[0] = TCPS_OPT_KIND;
	opt[1] = TCPS_OPT_LEN;
	opt[2] = (TCPS_OPT_MAGIC >> 8) & 0xff;
	opt[3] = TCPS_OPT_MAGIC & 0xff;

	th->doff += total / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) + total);
	skb_put(skb, total);
	tcps_recalc_csum(skb);
	return 1;
}

static int tcps_find_tm_option(const struct tcphdr *th, int tcplen,
			       uint8_t tag[TCPS_MAC_SIZE])
{
	int off = sizeof(*th);
	int end = tcps_opt_end(th, tcplen);
	const uint8_t *opt = (const uint8_t *)th;

	while (off + 1 < end) {
		if (opt[off] == 0)
			return 0;
		if (opt[off] == 1) {
			off++;
			continue;
		}
		if (off + opt[off + 1] > end || opt[off + 1] < 2)
			return 0;
		if (opt[off] == TCPS_TM_OPT_KIND && opt[off + 1] == TCPS_TM_OPT_LEN) {
			uint16_t magic = (uint16_t)opt[off + 2] << 8 |
					 (uint16_t)opt[off + 3];
			if (magic == TCPS_TM_OPT_MAGIC) {
				memcpy(tag, opt + off + 4, TCPS_MAC_SIZE);
				return 1;
			}
		}
		off += opt[off + 1];
	}
	return 0;
}

static int tcps_add_tm_option(struct sk_buff *skb, const uint8_t tag[TCPS_MAC_SIZE])
{
	struct iphdr *iph;
	struct tcphdr *th;
	int old_doff, total = TCPS_TM_OPT_LEN;
	int tcplen, payload_len;
	uint8_t *opt, *from, *to;

	if (skb_tailroom(skb) < total + 64) {
		if (pskb_expand_head(skb, 0, total + 64, GFP_ATOMIC))
			return 0;
	}

	iph = ip_hdr(skb);
	th = tcp_hdr(skb);
	old_doff = th->doff * 4;
	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	payload_len = tcplen - old_doff;
	if (payload_len < 0)
		payload_len = 0;
	if (old_doff + total > 60)
		return 0;

	skb_put(skb, total);

	from = (uint8_t *)th + old_doff;
	to = from + total;
	if (payload_len > 0)
		memmove(to, from, payload_len);

	opt = from;
	opt[0] = TCPS_TM_OPT_KIND;
	opt[1] = TCPS_TM_OPT_LEN;
	opt[2] = (TCPS_TM_OPT_MAGIC >> 8) & 0xff;
	opt[3] = TCPS_TM_OPT_MAGIC & 0xff;
	memcpy(opt + 4, tag, TCPS_MAC_SIZE);

	th->doff += total / 4;
	iph->tot_len = htons(ntohs(iph->tot_len) + total);
	return 1;
}

static uint64_t tcps_send_pos(struct tcps_conn *c, uint32_t seq)
{
	uint32_t base = c->is_client ? c->client_isn + 1 : c->server_isn + 1;
	uint32_t offset = seq - base;
	if (offset < c->enc_seq_hi)
		c->enc_seq_hi += 0x100000000ULL;
	return c->enc_seq_hi + offset;
}

static uint64_t tcps_recv_pos(struct tcps_conn *c, uint32_t seq)
{
	uint32_t base = c->is_client ? c->server_isn + 1 : c->client_isn + 1;
	uint32_t offset = seq - base;
	if (offset < c->dec_seq_hi)
		c->dec_seq_hi += 0x100000000ULL;
	return c->dec_seq_hi + offset;
}

static struct tcps_conn *tcps_conn_lookup(__be32 saddr, __be16 sport,
					  __be32 daddr, __be16 dport)
{
	struct tcps_conn *c;
	uint32_t h = jhash_3words((__force u32)saddr, (__force u32)daddr,
				  ((__force u32)sport << 16) | (__force u32)dport, 0);
	hash_for_each_possible_rcu(tcps_table, c, hnode, h) {
		if (c->saddr == saddr && c->daddr == daddr &&
		    c->sport == sport && c->dport == dport)
			return c;
	}
	return NULL;
}

static struct tcps_conn *tcps_conn_add(__be32 saddr, __be16 sport,
				       __be32 daddr, __be16 dport)
{
	struct tcps_conn *c;
	uint32_t h;

	c = kzalloc(sizeof(*c), GFP_ATOMIC);
	if (!c)
		return NULL;

	c->saddr = saddr;
	c->daddr = daddr;
	c->sport = sport;
	c->dport = dport;
	spin_lock_init(&c->lock);
	c->last_active = jiffies;

	h = jhash_3words((__force u32)saddr, (__force u32)daddr,
			 ((__force u32)sport << 16) | (__force u32)dport, 0);
	spin_lock(&tcps_lock);
	hash_add_rcu(tcps_table, &c->hnode, h);
	spin_unlock(&tcps_lock);
	return c;
}

static struct tcps_conn *tcps_conn_add_unique(__be32 saddr, __be16 sport,
					       __be32 daddr, __be16 dport)
{
	struct tcps_conn *c;

	c = tcps_conn_lookup(saddr, sport, daddr, dport);
	if (c)
		return c;
	c = tcps_conn_lookup(daddr, dport, saddr, sport);
	if (c)
		return c;
	return tcps_conn_add(saddr, sport, daddr, dport);
}

static void tcps_conn_free_rcu(struct rcu_head *rh)
{
	struct tcps_conn *c = container_of(rh, struct tcps_conn, rcu);
	memzero_explicit(c->enc_key, sizeof(c->enc_key));
	memzero_explicit(c->dec_key, sizeof(c->dec_key));
	memzero_explicit(c->mac_enc_key, sizeof(c->mac_enc_key));
	memzero_explicit(c->mac_dec_key, sizeof(c->mac_dec_key));
	kfree(c);
}

static void tcps_conn_remove(struct tcps_conn *c)
{
	spin_lock(&tcps_lock);
	hash_del_rcu(&c->hnode);
	spin_unlock(&tcps_lock);
	call_rcu(&c->rcu, tcps_conn_free_rcu);
}

static void tcps_derive_conn_keys(struct tcps_conn *c)
{
	uint8_t enc_key[TCPS_KEY_SIZE], dec_key[TCPS_KEY_SIZE];
	uint8_t mac_enc[TCPS_KEY_SIZE], mac_dec[TCPS_KEY_SIZE];
	uint8_t psk[32];
	__be32 peer_addr;
	int psk_ok;

	peer_addr = c->is_client ? c->daddr : c->saddr;

	psk_ok = tcps_peer_get_psk(peer_addr, psk);
	if (psk_ok < 0) {
		uint8_t dh_shared[32];
		struct tcps_peer *p;

		rcu_read_lock();
		p = tcps_peer_lookup(peer_addr);
		if (p && tcps_dh_shared(READ_ONCE(tcps_my_init_key[0]) ? tcps_my_init_key : tcps_my_init_key,
					p->public_key, dh_shared) == 0) {
			int i;
			uint8_t z = 0;
			for (i = 0; i < 32; i++)
				z |= dh_shared[i];
			if (z == 0) {
				rcu_read_unlock();
				memzero_explicit(dh_shared, sizeof(dh_shared));
				pr_warn("tcps: DH all-zero for %pI4 -> DH fallback\n",
					&peer_addr);
				memset(psk, 0, 32);
				goto derive;
			}
			tcps_derive_psk_fallback(dh_shared, psk);
		} else {
			rcu_read_unlock();
			memset(psk, 0, 32);
			pr_warn("tcps: PSK not ready for %pI4, using zero fallback\n",
				&peer_addr);
			goto derive;
		}
		rcu_read_unlock();
		memzero_explicit(dh_shared, sizeof(dh_shared));
		if (psk_ok == -EPERM)
			pr_warn("tcps: PSK not verified for %pI4, using DH fallback\n",
				&peer_addr);
		else
			pr_warn("tcps: PSK not ready for %pI4, using DH fallback\n",
				&peer_addr);
	}

derive:
	tcps_derive_keys(psk, c->client_isn, c->server_isn,
			 c->is_client, enc_key, dec_key, mac_enc, mac_dec);

	memcpy(c->enc_key, enc_key, TCPS_KEY_SIZE);
	memcpy(c->dec_key, dec_key, TCPS_KEY_SIZE);
	memcpy(c->mac_enc_key, mac_enc, TCPS_KEY_SIZE);
	memcpy(c->mac_dec_key, mac_dec, TCPS_KEY_SIZE);
	memzero_explicit(enc_key, sizeof(enc_key));
	memzero_explicit(dec_key, sizeof(dec_key));
	memzero_explicit(mac_enc, sizeof(mac_enc));
	memzero_explicit(mac_dec, sizeof(mac_dec));
	memzero_explicit(psk, sizeof(psk));

	c->keys_derived = 1;
	c->state = TCPS_KEYED;
}

static int tcps_is_fragment(struct sk_buff *skb)
{
	if (!skb || skb->len < (int)sizeof(struct iphdr))
		return 1;
	return ip_hdr(skb)->frag_off & htons(IP_OFFSET | IP_MF);
}

static void tcps_build_aad(uint8_t aad[5], struct tcphdr *th)
{
	aad[0] = ((uint8_t *)th)[13];
	aad[1] = (uint8_t)(ntohl(th->seq));
	aad[2] = (uint8_t)(ntohl(th->seq) >> 8);
	aad[3] = (uint8_t)(ntohl(th->seq) >> 16);
	aad[4] = (uint8_t)(ntohl(th->seq) >> 24);
}

static unsigned int tcps_out(void *priv, struct sk_buff *skb,
			     const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	struct tcps_conn *c;
	int payload_off, payload_len;
	uint64_t pos;

	if (!skb || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	if (tcps_is_fragment(skb))
		return NF_ACCEPT;
	if (skb_linearize(skb))
		return NF_DROP;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	if (ntohl(iph->daddr) >> 24 == 127)
		return NF_ACCEPT;
	th = tcp_hdr(skb);
	if (!th)
		return NF_DROP;

	rcu_read_lock();

	if (th->syn && !th->ack) {
		int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

		if (tcps_should_skip(th->dest) || tcps_should_skip(th->source)) {
			rcu_read_unlock();
			return NF_ACCEPT;
		}

		if (!tcps_has_probe(th, tcplen)) {
			if (tcps_add_probe(skb)) {
				iph = ip_hdr(skb);
				th = tcp_hdr(skb);
				c = tcps_conn_add_unique(iph->saddr, th->source,
							 iph->daddr, th->dest);
				if (c) {
					spin_lock_bh(&c->lock);
					if (c->state == TCPS_NONE) {
						c->state = TCPS_PROBE_SYN;
						c->is_client = 1;
						c->client_isn = ntohl(th->seq);
					}
					c->last_active = jiffies;
					spin_unlock_bh(&c->lock);
				}
				tcps_trigger_discover(iph->daddr);
			}
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	c = tcps_conn_lookup(iph->saddr, th->source, iph->daddr, th->dest);
	if (!c) {
		c = tcps_conn_lookup(iph->daddr, th->dest, iph->saddr, th->source);
		if (!c) {
			rcu_read_unlock();
			return NF_ACCEPT;
		}
	}

	spin_lock_bh(&c->lock);
	c->last_active = jiffies;

	if (th->syn && th->ack) {
		if (c->state == TCPS_PROBE_SYNACK || c->state == TCPS_KEYED) {
			c->server_isn = ntohl(th->seq);
			tcps_add_probe(skb);
			if (c->client_isn && c->server_isn && !c->keys_derived)
				tcps_derive_conn_keys(c);
		}
		spin_unlock_bh(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (c->state != TCPS_KEYED) {
		spin_unlock_bh(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->rst) {
		c->kill = 1;
		c->state = TCPS_DEAD;
		spin_unlock_bh(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (skb_is_gso(skb)) {
		spin_unlock_bh(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	payload_off = iph->ihl * 4 + th->doff * 4;
	payload_len = skb->len - payload_off;
	if (payload_len < 0)
		payload_len = 0;

	if (payload_len > 0 && c->keys_derived) {
		if (payload_off + payload_len > skb->len) {
			spin_unlock_bh(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		pos = tcps_send_pos(c, ntohl(th->seq));
		chacha20_xor_stream(c->enc_key, pos,
				    (uint8_t *)th + th->doff * 4, payload_len);

		{
			uint8_t aad[5];
			uint8_t tag[TCPS_TAG_SIZE];

			tcps_build_aad(aad, th);
			tcps_compute_mac(c->mac_enc_key, pos, aad, 5,
					 (uint8_t *)th + th->doff * 4,
					 payload_len, tag);
			if (tcps_add_tm_option(skb, tag)) {
				iph = ip_hdr(skb);
				th = tcp_hdr(skb);
				tcps_recalc_csum(skb);
			}
		}
	}

	if (th->fin) {
		c->fin_out = 1;
		if (c->fin_in)
			c->kill = 1;
	}

	spin_unlock_bh(&c->lock);
	rcu_read_unlock();
	return NF_ACCEPT;
}

static unsigned int tcps_in(void *priv, struct sk_buff *skb,
			    const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	struct tcps_conn *c;
	int payload_off, payload_len;
	uint64_t pos;

	if (!skb || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	if (tcps_is_fragment(skb))
		return NF_ACCEPT;
	if (skb->len < sizeof(struct iphdr))
		return NF_DROP;
	if (skb_linearize(skb))
		return NF_DROP;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	if (ntohl(iph->saddr) >> 24 == 127)
		return NF_ACCEPT;
	th = tcp_hdr(skb);
	if (!th)
		return NF_DROP;

	rcu_read_lock();

	if (th->syn && !th->ack) {
		int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

		if (tcps_should_skip(th->dest) || tcps_should_skip(th->source)) {
			rcu_read_unlock();
			return NF_ACCEPT;
		}

		if (tcps_has_probe(th, tcplen)) {
			c = tcps_conn_add_unique(iph->saddr, th->source,
						 iph->daddr, th->dest);
			if (c) {
				spin_lock_bh(&c->lock);
				if (c->state == TCPS_NONE) {
					c->state = TCPS_PROBE_SYNACK;
					c->is_client = 0;
					c->client_isn = ntohl(th->seq);
				}
				c->last_active = jiffies;
				spin_unlock_bh(&c->lock);
			}
			tcps_trigger_discover(iph->saddr);
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->syn && th->ack) {
		int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
		int has_probe = tcps_has_probe(th, tcplen);

		c = tcps_conn_lookup(iph->daddr, th->dest, iph->saddr, th->source);
		if (c) {
			spin_lock_bh(&c->lock);
			if (c->state == TCPS_PROBE_SYN && has_probe) {
				c->server_isn = ntohl(th->seq);
				if (c->client_isn && c->server_isn && !c->keys_derived)
					tcps_derive_conn_keys(c);
			} else if (c->state == TCPS_PROBE_SYN && !has_probe) {
				spin_unlock_bh(&c->lock);
				tcps_conn_remove(c);
				rcu_read_unlock();
				return NF_ACCEPT;
			}
			spin_unlock_bh(&c->lock);
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	c = tcps_conn_lookup(iph->daddr, th->dest, iph->saddr, th->source);
	if (!c) {
		c = tcps_conn_lookup(iph->saddr, th->source, iph->daddr, th->dest);
		if (!c) {
			rcu_read_unlock();
			return NF_ACCEPT;
		}
	}

	spin_lock_bh(&c->lock);
	c->last_active = jiffies;

	if (c->state != TCPS_KEYED) {
		spin_unlock_bh(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->rst) {
		int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
		uint8_t recv_tag[TCPS_MAC_SIZE];

		if (c->peer_has_mac && !tcps_find_tm_option(th, tcplen, recv_tag)) {
			pr_warn("tcps: RST without MAC from %pI4 -> DROP (injection?)\n",
				&iph->saddr);
			spin_unlock_bh(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}
		c->kill = 1;
		spin_unlock_bh(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	payload_off = iph->ihl * 4 + th->doff * 4;
	payload_len = ntohs(iph->tot_len) - payload_off;
	if (payload_len < 0)
		payload_len = 0;

	if (payload_len > 0 && c->keys_derived) {
		int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
		uint8_t recv_tag[TCPS_MAC_SIZE];
		int has_tm = tcps_find_tm_option(th, tcplen, recv_tag);

		if (has_tm) {
			uint8_t aad[5];
			uint8_t exp_tag[TCPS_TAG_SIZE];

			pos = tcps_recv_pos(c, ntohl(th->seq));

			tcps_build_aad(aad, th);
			tcps_compute_mac(c->mac_dec_key, pos, aad, 5,
					 (uint8_t *)th + th->doff * 4,
					 payload_len, exp_tag);

			if (tcps_ct_memcmp(recv_tag, exp_tag, TCPS_MAC_SIZE) != 0) {
				pr_warn("tcps: MAC FAILED from %pI4 -> DROP (tampering?)\n",
					&iph->saddr);
				memzero_explicit(exp_tag, sizeof(exp_tag));
				spin_unlock_bh(&c->lock);
				rcu_read_unlock();
				return NF_DROP;
			}
			memzero_explicit(exp_tag, sizeof(exp_tag));
			c->peer_has_mac = 1;
		} else if (c->peer_has_mac) {
			pr_warn_ratelimited("tcps: no MAC from %pI4 -> DROP\n",
					    &iph->saddr);
			spin_unlock_bh(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		pos = tcps_recv_pos(c, ntohl(th->seq));

		if (payload_off + payload_len > skb->len) {
			spin_unlock_bh(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		chacha20_xor_stream(c->dec_key, pos,
				    (uint8_t *)th + th->doff * 4, payload_len);
		tcps_recalc_csum(skb);
	}

	if (th->fin) {
		c->fin_in = 1;
		if (c->fin_out)
			c->kill = 1;
	}

	spin_unlock_bh(&c->lock);
	rcu_read_unlock();
	return NF_ACCEPT;
}

static const struct nf_hook_ops tcps_nf_ops[] = {
	{
		.hook = tcps_out,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_OUT,
		.priority = NF_IP_PRI_FIRST,
	},
	{
		.hook = tcps_in,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_FIRST + 1,
	},
};

static void tcps_cleanup_work(struct work_struct *w)
{
	struct tcps_conn *c;
	int i;

	rcu_read_lock();
	hash_for_each_rcu(tcps_table, i, c, hnode) {
		if (c->kill || (c->state == TCPS_DEAD &&
				 time_after(jiffies, c->last_active + HZ * 30)))
			tcps_conn_remove(c);
	}
	rcu_read_unlock();
}

static DECLARE_DELAYED_WORK(tcps_cleanup, tcps_cleanup_work);

static void tcps_send_keyxchg(struct socket *sock, __be32 peer_addr,
			      const uint8_t peer_pub[32])
{
	struct tcps_disc_pkt pkt;
	struct sockaddr_in addr;
	struct msghdr msg = {};
	struct kvec iov;
	uint8_t dh_shared[32];
	uint8_t prev_psk[32];
	int has_prev;

	if (tcps_dh_shared(tcps_my_init_key, peer_pub, dh_shared) < 0) {
		memzero_explicit(dh_shared, sizeof(dh_shared));
		return;
	}

	memset(&pkt, 0, sizeof(pkt));
	pkt.magic = htonl(TCPS_DISC_MAGIC);
	pkt.type = TCPS_DISC_TYPE_KEYXCHG;
	memcpy(pkt.pubkey, tcps_my_public, CURVE25519_KEY_SIZE);
	memcpy(pkt.enc_init, tcps_my_init_key, CURVE25519_KEY_SIZE);
	chacha20_xor_stream(dh_shared, 0, pkt.enc_init, CURVE25519_KEY_SIZE);

	has_prev = tcps_peer_get_prev_psk(peer_addr, prev_psk);
	if (has_prev == 0) {
		uint8_t auth_data[65];
		uint8_t auth_tag[TCPS_TAG_SIZE];

		pkt.type = TCPS_DISC_TYPE_KEYXCHG_AUTH;
		memcpy(auth_data, &pkt.type, 1);
		memcpy(auth_data + 1, pkt.pubkey, 32);
		memcpy(auth_data + 33, pkt.enc_init, 32);
		tcps_compute_mac(prev_psk, 0, auth_data, 65, NULL, 0, auth_tag);
		memcpy(pkt.auth_tag, auth_tag, TCPS_MAC_SIZE);
		memzero_explicit(auth_tag, sizeof(auth_tag));
		memzero_explicit(auth_data, sizeof(auth_data));
		memzero_explicit(prev_psk, sizeof(prev_psk));
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCPS_DISC_PORT);
	addr.sin_addr.s_addr = peer_addr;

	iov.iov_base = &pkt;
	if (pkt.type == TCPS_DISC_TYPE_KEYXCHG_AUTH)
		iov.iov_len = sizeof(pkt);
	else
		iov.iov_len = offsetof(struct tcps_disc_pkt, auth_tag);
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
	memzero_explicit(dh_shared, sizeof(dh_shared));
}

#define TCPS_DISC_MIN_SIZE	offsetof(struct tcps_disc_pkt, enc_init)

static int tcps_disc_recv(struct socket *sock)
{
	struct tcps_disc_pkt pkt;
	struct sockaddr_in addr;
	struct msghdr msg = {};
	struct kvec iov = {
		.iov_base = &pkt,
		.iov_len = sizeof(pkt),
	};
	int ret;

	memset(&addr, 0, sizeof(addr));
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	ret = kernel_recvmsg(sock, &msg, &iov, 1, sizeof(pkt), MSG_DONTWAIT);
	if (ret < (int)TCPS_DISC_MIN_SIZE)
		return ret;

	if (pkt.magic != htonl(TCPS_DISC_MAGIC))
		return -EINVAL;

	if (memcmp(pkt.pubkey, tcps_my_public, CURVE25519_KEY_SIZE) == 0)
		return 0;

	if (pkt.type == TCPS_DISC_TYPE_DISCOVER) {
		uint8_t peer_pub[32];

		memcpy(peer_pub, pkt.pubkey, 32);
		tcps_peer_add(addr.sin_addr.s_addr, peer_pub);
		tcps_send_keyxchg(sock, addr.sin_addr.s_addr, peer_pub);

	} else if (pkt.type == TCPS_DISC_TYPE_KEYXCHG ||
		   pkt.type == TCPS_DISC_TYPE_KEYXCHG_AUTH) {
		struct tcps_peer *p;
		uint8_t dh_shared[32];
		uint8_t peer_init_key[32];
		uint8_t psk[32];
		uint8_t peer_pub[32];
		__be32 peer_addr = addr.sin_addr.s_addr;
		int has_prev;
		uint8_t prev_psk[32];

		if (ret < (int)offsetof(struct tcps_disc_pkt, auth_tag))
			return -EINVAL;

		memcpy(peer_pub, pkt.pubkey, 32);
		tcps_peer_add(peer_addr, peer_pub);

		has_prev = tcps_peer_get_prev_psk(peer_addr, prev_psk);

		if (pkt.type == TCPS_DISC_TYPE_KEYXCHG && has_prev == 0) {
			pr_warn("tcps: KEYXCHG without auth from %pI4 but we have prev PSK -> WARN (peer reload?)\n",
				&peer_addr);
		}

		if (pkt.type == TCPS_DISC_TYPE_KEYXCHG_AUTH) {
			if (ret < (int)sizeof(pkt))
				return -EINVAL;

			if (has_prev != 0) {
				pr_warn("tcps: KEYXCHG_AUTH from %pI4 but no prev PSK -> WARN, accepting as plain KEYXCHG\n",
					&peer_addr);
			} else {
				uint8_t auth_data[65];
				uint8_t exp_tag[TCPS_TAG_SIZE];

				auth_data[0] = TCPS_DISC_TYPE_KEYXCHG_AUTH;
				memcpy(auth_data + 1, pkt.pubkey, 32);
				memcpy(auth_data + 33, pkt.enc_init, 32);
				tcps_compute_mac(prev_psk, 0, auth_data, 65,
						 NULL, 0, exp_tag);

				if (tcps_ct_memcmp(pkt.auth_tag, exp_tag, TCPS_MAC_SIZE) != 0) {
					pr_warn("tcps: KEYXCHG_AUTH FAILED from %pI4 (prev_psk mismatch, rotation race?) -> continuing as plain KEYXCHG\n",
						 &peer_addr);
					memzero_explicit(exp_tag, sizeof(exp_tag));
					memzero_explicit(prev_psk, sizeof(prev_psk));
					memzero_explicit(auth_data, sizeof(auth_data));
				} else {
					memzero_explicit(exp_tag, sizeof(exp_tag));
					memzero_explicit(auth_data, sizeof(auth_data));
					pr_info("tcps: KEYXCHG_AUTH verified from %pI4\n",
						&peer_addr);
				}
			}
			memzero_explicit(prev_psk, sizeof(prev_psk));
		}

		{
			uint8_t try_priv[2][32];
			int n_keys = 1;
			int ki;
			int found = 0;

			spin_lock(&tcps_peers_lock);
			memcpy(try_priv[0], tcps_my_init_key, 32);
			if (tcps_has_prev_init) {
				memcpy(try_priv[1], tcps_prev_init_key, 32);
				n_keys = 2;
			}
			spin_unlock(&tcps_peers_lock);

			for (ki = 0; ki < n_keys && !found; ki++) {
				uint8_t trial_dh[32];
				uint8_t trial_init[32];
				uint8_t trial_pub[32];

				if (tcps_dh_shared(try_priv[ki], peer_pub, trial_dh) < 0)
					continue;

				memcpy(trial_init, pkt.enc_init, 32);
				chacha20_xor_stream(trial_dh, 0, trial_init, 32);

				if (!curve25519_generate_public(trial_pub, trial_init))
					continue;
				if (memcmp(trial_pub, peer_pub, 32) != 0) {
					memzero_explicit(trial_dh, 32);
					memzero_explicit(trial_init, 32);
					memzero_explicit(trial_pub, 32);
					continue;
				}

				memcpy(dh_shared, trial_dh, 32);
				memcpy(peer_init_key, trial_init, 32);
				found = 1;
				memzero_explicit(trial_dh, 32);
				memzero_explicit(trial_init, 32);
				memzero_explicit(trial_pub, 32);
			}

			for (ki = 0; ki < n_keys; ki++)
				memzero_explicit(try_priv[ki], 32);

			if (!found) {
				memzero_explicit(dh_shared, sizeof(dh_shared));
				pr_warn("tcps: KEYXCHG from %pI4: no matching init_key (rotation race?)\n",
					&peer_addr);
				return 0;
			}
		}

		if (memcmp(tcps_my_public, peer_pub, 32) < 0)
			tcps_derive_psk(dh_shared, tcps_my_init_key,
					peer_init_key, psk);
		else
			tcps_derive_psk(dh_shared, peer_init_key,
					tcps_my_init_key, psk);

		tcps_peer_set_psk(peer_addr, psk);
		{
			int k;
			pr_info("tcps: PSK established with %pI4 fingerprint=", &peer_addr);
			for (k = 0; k < 8; k++)
				pr_cont("%02x", psk[k]);
			pr_cont("\n");
		}

		memzero_explicit(dh_shared, sizeof(dh_shared));
		memzero_explicit(peer_init_key, sizeof(peer_init_key));
		memzero_explicit(psk, sizeof(psk));
	}

	return 0;
}

static void tcps_send_discover_unicast(struct socket *sock, __be32 peer_addr)
{
	struct tcps_disc_pkt pkt;
	struct sockaddr_in addr;
	struct msghdr msg = {};
	struct kvec iov;

	memset(&pkt, 0, sizeof(pkt));
	pkt.magic = htonl(TCPS_DISC_MAGIC);
	pkt.type = TCPS_DISC_TYPE_DISCOVER;
	memcpy(pkt.pubkey, tcps_my_public, CURVE25519_KEY_SIZE);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCPS_DISC_PORT);
	addr.sin_addr.s_addr = peer_addr;

	iov.iov_base = &pkt;
	iov.iov_len = offsetof(struct tcps_disc_pkt, enc_init);
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
}

static void tcps_disc_send(struct socket *sock)
{
	struct tcps_peer *p;
	int i;

	rcu_read_lock();
	hash_for_each_rcu(tcps_peers, i, p, hnode) {
		if (!p->psk_ready)
			tcps_send_discover_unicast(sock, p->addr);
	}
	rcu_read_unlock();
}

struct tcps_disc_work {
	struct work_struct work;
	__be32 peer_addr;
};

static void tcps_trigger_discover_work(struct work_struct *w)
{
	struct tcps_disc_work *dw = container_of(w, struct tcps_disc_work, work);
	struct tcps_peer *p;
	struct socket *sock;

	sock = READ_ONCE(tcps_disc_sock);
	if (!sock)
		goto out;
	if (dw->peer_addr == 0 || dw->peer_addr == htonl(INADDR_BROADCAST))
		goto out;

	rcu_read_lock();
	p = tcps_peer_lookup(dw->peer_addr);
	if (p && p->psk_ready) {
		rcu_read_unlock();
		goto out;
	}
	rcu_read_unlock();

	tcps_send_discover_unicast(sock, dw->peer_addr);
out:
	kfree(dw);
}

static void tcps_trigger_discover(__be32 peer_addr)
{
	struct tcps_disc_work *dw;

	if (peer_addr == 0 || peer_addr == htonl(INADDR_BROADCAST))
		return;

	dw = kmalloc(sizeof(*dw), GFP_ATOMIC);
	if (!dw)
		return;
	INIT_WORK(&dw->work, tcps_trigger_discover_work);
	dw->peer_addr = peer_addr;
	schedule_work(&dw->work);
}

static int tcps_disc_thread(void *data)
{
	struct socket *sock;
	struct sockaddr_in addr;
	int ret;

	ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret)
		return ret;

	sock->sk->sk_rcvtimeo = HZ;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCPS_DISC_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret) {
		sock_release(sock);
		return ret;
	}

	WRITE_ONCE(tcps_disc_sock, sock);

	while (!kthread_should_stop()) {
		tcps_disc_send(sock);

		while (!kthread_should_stop())
			if (tcps_disc_recv(sock) < 0)
				break;

		schedule_timeout_interruptible(HZ * 3);
	}

	WRITE_ONCE(tcps_disc_sock, NULL);
	sock_release(sock);
	return 0;
}

static void tcps_rotate_init_key(struct work_struct *w)
{
	uint8_t old_key[CURVE25519_KEY_SIZE];

	memcpy(old_key, tcps_my_init_key, CURVE25519_KEY_SIZE);

	spin_lock(&tcps_peers_lock);
	memcpy(tcps_prev_init_key, tcps_my_init_key, CURVE25519_KEY_SIZE);
	tcps_has_prev_init = 1;
	tcps_gen_keypair(tcps_my_init_key, tcps_my_public);
	spin_unlock(&tcps_peers_lock);

	{
		int i;
		pr_info("tcps: init-key ROTATED, new pubkey=");
		for (i = 0; i < 8; i++)
			pr_cont("%02x", tcps_my_public[i]);
		pr_cont("...\n");
	}

	memzero_explicit(old_key, sizeof(old_key));

	{
		struct socket *sock = READ_ONCE(tcps_disc_sock);
		if (sock) {
			struct tcps_peer *p;
			int i;
			__be32 addrs[TCPS_MAX_PEERS];
			int count = 0;

			rcu_read_lock();
			hash_for_each_rcu(tcps_peers, i, p, hnode) {
				if (count < TCPS_MAX_PEERS)
					addrs[count++] = p->addr;
			}
			rcu_read_unlock();

			for (i = 0; i < count; i++)
				tcps_send_discover_unicast(sock, addrs[i]);
		}
	}

	schedule_delayed_work(container_of(w, struct delayed_work, work),
			      tcps_rotate_interval * HZ);
}

static DECLARE_DELAYED_WORK(tcps_key_rotate, tcps_rotate_init_key);

static ssize_t tcps_peers_proc_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char kbuf[160];
	uint8_t pubkey[32];
	uint8_t fingerprint[8];
	__be32 addr;
	int i;
	char *p, *cmd;

	if (count > sizeof(kbuf) - 1)
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = 0;

	cmd = strstrip(kbuf);

	if (strncmp(cmd, "verify ", 7) == 0) {
		cmd += 7;
		p = strchr(cmd, ' ');
		if (!p)
			return -EINVAL;
		*p = 0;
		if (!in4_pton(cmd, -1, (u8 *)&addr, -1, NULL))
			return -EINVAL;
		p++;
		if (strlen(p) < 16)
			return -EINVAL;
		for (i = 0; i < 8; i++) {
			unsigned int byte;
			if (sscanf(p + i * 2, "%02x", &byte) != 1)
				return -EINVAL;
			fingerprint[i] = byte;
		}
		return tcps_peer_verify_psk(addr, fingerprint) ? : count;
	}

	p = strchr(cmd, '=');
	if (!p)
		return -EINVAL;
	*p = 0;
	if (!in4_pton(cmd, -1, (u8 *)&addr, -1, NULL))
		return -EINVAL;
	p++;

	for (i = 0; i < 32; i++) {
		unsigned int byte;
		if (sscanf(p + i * 2, "%02x", &byte) != 1)
			return -EINVAL;
		pubkey[i] = byte;
	}

	tcps_peer_add(addr, pubkey);
	return count;
}

static int tcps_peers_proc_show(struct seq_file *m, void *v)
{
	struct tcps_peer *p;
	int i, j;

	rcu_read_lock();
	hash_for_each_rcu(tcps_peers, i, p, hnode) {
		seq_printf(m, "%pI4 pub=", &p->addr);
		for (j = 0; j < 32; j++)
			seq_printf(m, "%02x", p->public_key[j]);
		if (p->psk_ready) {
			seq_printf(m, " psk=%s fp=", p->psk_verified ? "verified" : "unverified");
			for (j = 0; j < 8; j++)
				seq_printf(m, "%02x", p->psk_fingerprint[j]);
		} else {
			seq_printf(m, " psk=pending");
		}
		if (p->has_prev_psk)
			seq_printf(m, " prev=1");
		seq_putc(m, '\n');
	}
	rcu_read_unlock();
	return 0;
}

static int tcps_peers_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tcps_peers_proc_show, NULL);
}

static const struct proc_ops tcps_peers_proc_ops = {
	.proc_open	= tcps_peers_proc_open,
	.proc_read	= seq_read,
	.proc_write	= tcps_peers_proc_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int __init tcps_init(void)
{
	tcps_gen_keypair(tcps_my_init_key, tcps_my_public);

	pr_info("tcps: X25519 init-key generated, pubkey=");
	{
		int i;
		for (i = 0; i < 8; i++)
			pr_cont("%02x", tcps_my_public[i]);
		pr_cont("...\n");
	}

	nf_register_net_hooks(&init_net, tcps_nf_ops, ARRAY_SIZE(tcps_nf_ops));

	proc_create("tcps_peers", 0644, NULL, &tcps_peers_proc_ops);

	tcps_disc_task = kthread_run(tcps_disc_thread, NULL, "tcps_disc");
	if (IS_ERR(tcps_disc_task))
		tcps_disc_task = NULL;

	schedule_delayed_work(&tcps_cleanup, HZ * 60);
	schedule_delayed_work(&tcps_key_rotate, tcps_rotate_interval * HZ);

	pr_info("tcps: module loaded, X25519+ChaCha20-Poly1305+PSK+FS active (rotate=%ds)\n",
		tcps_rotate_interval);
	return 0;
}

static void __exit tcps_exit(void)
{
	struct tcps_conn *c;
	struct tcps_peer *p;
	int i;

	cancel_delayed_work_sync(&tcps_cleanup);
	cancel_delayed_work_sync(&tcps_key_rotate);
	nf_unregister_net_hooks(&init_net, tcps_nf_ops, ARRAY_SIZE(tcps_nf_ops));

	if (tcps_disc_task)
		kthread_stop(tcps_disc_task);

	flush_scheduled_work();

	remove_proc_entry("tcps_peers", NULL);

	rcu_read_lock();
	hash_for_each_rcu(tcps_table, i, c, hnode)
		tcps_conn_remove(c);
	hash_for_each_rcu(tcps_peers, i, p, hnode) {
		spin_lock(&tcps_peers_lock);
		hash_del_rcu(&p->hnode);
		spin_unlock(&tcps_peers_lock);
		call_rcu(&p->rcu, tcps_peer_free_rcu);
	}
	rcu_read_unlock();
	synchronize_rcu();

	memzero_explicit(tcps_my_init_key, sizeof(tcps_my_init_key));
	memzero_explicit(tcps_prev_init_key, sizeof(tcps_prev_init_key));
	pr_info("tcps: module unloaded\n");
}

module_init(tcps_init);
module_exit(tcps_exit);
