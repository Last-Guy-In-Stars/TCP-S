#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/hashtable.h>
#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/workqueue.h>
#include <net/checksum.h>
#include <crypto/algapi.h>
#include "tcps.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tcps");
MODULE_DESCRIPTION("Transparent TCP stream encryption: ECDH (X25519) + ChaCha20-Poly1305");
MODULE_SOFTDEP("pre: libcurve25519");

static DEFINE_HASHTABLE(tcps_table, TCPS_HASH_BITS);
static DEFINE_SPINLOCK(tcps_lock);

static void tcps_gc(struct work_struct *work);
static DECLARE_DELAYED_WORK(tcps_gc_work, tcps_gc);

static void tcps_conn_free_rcu(struct rcu_head *head);

static inline uint32_t tcps_hash4(__be32 a1, __be16 p1,
				  __be32 a2, __be16 p2)
{
	uint32_t words[3];
	__be32 t32;
	__be16 t16;

	if (a1 > a2 || (a1 == a2 && p1 > p2)) {
		t32 = a1; a1 = a2; a2 = t32;
		t16 = p1; p1 = p2; p2 = t16;
	}
	words[0] = a1;
	words[1] = a2;
	words[2] = ((uint32_t)p1 << 16) | (uint32_t)p2;
	return jhash2(words, 3, 0);
}

static inline uint64_t tcps_send_pos(struct tcps_conn *c, uint32_t seq)
{
	uint32_t isn = c->is_client ? c->client_isn : c->server_isn;
	uint64_t base = (uint64_t)c->send_wrap << 32;
	return base + (uint64_t)(seq - isn - 1);
}

static inline uint64_t tcps_recv_pos(struct tcps_conn *c, uint32_t seq)
{
	uint32_t isn = c->is_client ? c->server_isn : c->client_isn;
	uint64_t base = (uint64_t)c->recv_wrap << 32;
	return base + (uint64_t)(seq - isn - 1);
}

static inline void tcps_update_send_wrap(struct tcps_conn *c, uint32_t seq)
{
	int32_t diff = (int32_t)(seq - c->last_send_seq);
	if (diff < 0 && c->last_send_seq != 0)
		c->send_wrap++;
	c->last_send_seq = seq;
}

static inline void tcps_update_recv_wrap(struct tcps_conn *c, uint32_t seq)
{
	int32_t diff = (int32_t)(seq - c->last_recv_seq);
	if (diff < 0 && c->last_recv_seq != 0)
		c->recv_wrap++;
	c->last_recv_seq = seq;
}

struct tcps_conn *tcps_conn_find(__be32 saddr, __be16 sport,
				 __be32 daddr, __be16 dport)
{
	uint32_t h;
	struct tcps_conn *c;

	h = tcps_hash4(saddr, sport, daddr, dport);
	hash_for_each_possible_rcu(tcps_table, c, hnode, h) {
		if (c->saddr == saddr && c->daddr == daddr &&
		    c->sport == sport && c->dport == dport)
			return c;
	}
	return NULL;
}

struct tcps_conn *tcps_conn_find_any(__be32 a1, __be16 p1,
				     __be32 a2, __be16 p2)
{
	uint32_t h;
	struct tcps_conn *c;

	h = tcps_hash4(a1, p1, a2, p2);
	hash_for_each_possible_rcu(tcps_table, c, hnode, h) {
		if ((c->saddr == a1 && c->daddr == a2 &&
		     c->sport == p1 && c->dport == p2) ||
		    (c->saddr == a2 && c->daddr == a1 &&
		     c->sport == p2 && c->dport == p1))
			return c;
	}
	return NULL;
}

struct tcps_conn *tcps_conn_add(__be32 saddr, __be16 sport,
				__be32 daddr, __be16 dport)
{
	struct tcps_conn *c;
	uint32_t h;

	h = tcps_hash4(saddr, sport, daddr, dport);
	spin_lock(&tcps_lock);
	hash_for_each_possible(tcps_table, c, hnode, h) {
		if ((c->saddr == saddr && c->daddr == daddr &&
		     c->sport == sport && c->dport == dport) ||
		    (c->saddr == daddr && c->daddr == saddr &&
		     c->sport == dport && c->dport == sport)) {
			if (c->state == TCPS_DEAD) {
				hash_del_rcu(&c->hnode);
				call_rcu(&c->rcu, tcps_conn_free_rcu);
				break;
			}
			spin_unlock(&tcps_lock);
			return c;
		}
	}
	c = kzalloc(sizeof(*c), GFP_ATOMIC);
	if (!c) {
		spin_unlock(&tcps_lock);
		return NULL;
	}
	c->saddr = saddr;
	c->daddr = daddr;
	c->sport = sport;
	c->dport = dport;
	c->last_active = jiffies;
	spin_lock_init(&c->lock);
	tcps_dh_keygen(c->dh_priv, c->dh_pub);
	hash_add_rcu(tcps_table, &c->hnode, h);
	spin_unlock(&tcps_lock);
	return c;
}

static void tcps_conn_free_rcu(struct rcu_head *head)
{
	struct tcps_conn *c = container_of(head, struct tcps_conn, rcu);
	memzero_explicit(c->dh_priv, sizeof(c->dh_priv));
	memzero_explicit(c->dh_pub, sizeof(c->dh_pub));
	memzero_explicit(c->dh_peer_pub, sizeof(c->dh_peer_pub));
	memzero_explicit(c->enc_key, sizeof(c->enc_key));
	memzero_explicit(c->dec_key, sizeof(c->dec_key));
	memzero_explicit(c->mac_enc_key, sizeof(c->mac_enc_key));
	memzero_explicit(c->mac_dec_key, sizeof(c->mac_dec_key));
	kfree(c);
}

void tcps_conn_del(struct tcps_conn *c)
{
	spin_lock(&tcps_lock);
	hash_del_rcu(&c->hnode);
	spin_unlock(&tcps_lock);
	call_rcu(&c->rcu, tcps_conn_free_rcu);
}

void tcps_conn_cleanup(void)
{
	struct tcps_conn *c;
	struct hlist_node *tmp;
	unsigned bkt;
	hash_for_each_safe(tcps_table, bkt, tmp, c, hnode) {
		hash_del(&c->hnode);
		memzero_explicit(c->dh_priv, sizeof(c->dh_priv));
		memzero_explicit(c->dh_pub, sizeof(c->dh_pub));
		memzero_explicit(c->dh_peer_pub, sizeof(c->dh_peer_pub));
		memzero_explicit(c->enc_key, sizeof(c->enc_key));
		memzero_explicit(c->dec_key, sizeof(c->dec_key));
		memzero_explicit(c->mac_enc_key, sizeof(c->mac_enc_key));
		memzero_explicit(c->mac_dec_key, sizeof(c->mac_dec_key));
		kfree(c);
	}
}

static void tcps_gc(struct work_struct *work)
{
	struct tcps_conn *c;
	struct hlist_node *tmp;
	unsigned bkt;
	unsigned long now = jiffies;
	int del;

	spin_lock(&tcps_lock);
	hash_for_each_safe(tcps_table, bkt, tmp, c, hnode) {
		del = 0;
		spin_lock(&c->lock);
		if (c->state == TCPS_DEAD &&
		    time_after(now, c->last_active + TCPS_DEAD_TIMEOUT))
			del = 1;
		else if (c->fin_out && c->fin_in &&
			 time_after(now, c->last_active + TCPS_FIN_TIMEOUT))
			del = 1;
		else if (time_after(now, c->last_active + TCPS_IDLE_TIMEOUT))
			del = 1;
		spin_unlock(&c->lock);
		if (del) {
			hash_del_rcu(&c->hnode);
			call_rcu(&c->rcu, tcps_conn_free_rcu);
		}
	}
	spin_unlock(&tcps_lock);
	schedule_delayed_work(&tcps_gc_work, TCPS_GC_INTERVAL);
}

static int tcp_option_find_tcps(struct tcphdr *th,
				uint8_t peer_pub[TCPS_DH_SIZE])
{
	int optlen = th->doff * 4 - sizeof(struct tcphdr);
	uint8_t *opt = (uint8_t *)th + sizeof(struct tcphdr);
	int i = 0;
	int len;

	while (i < optlen) {
		if (opt[i] == 0)
			break;
		if (opt[i] == 1) {
			i++;
			continue;
		}
		if (i + 1 >= optlen)
			break;
		len = opt[i + 1];
		if (len < 2)
			break;
		if (opt[i] == TCPS_OPT_KIND && len == TCPS_OPT_LEN &&
		    opt[i + 2] == TCPS_OPT_MAGIC0 &&
		    opt[i + 3] == TCPS_OPT_MAGIC1) {
			if (peer_pub)
				memcpy(peer_pub, opt + i + 4, TCPS_DH_SIZE);
			return 1;
		}
		i += len;
	}
	return 0;
}

static int tcp_option_find_mac(struct tcphdr *th,
			       uint8_t tag[TCPS_MAC_TAG_SIZE])
{
	int optlen = th->doff * 4 - sizeof(struct tcphdr);
	uint8_t *opt = (uint8_t *)th + sizeof(struct tcphdr);
	int i = 0;
	int len;

	while (i < optlen) {
		if (opt[i] == 0)
			break;
		if (opt[i] == 1) {
			i++;
			continue;
		}
		if (i + 1 >= optlen)
			break;
		len = opt[i + 1];
		if (len < 2)
			break;
		if (opt[i] == TCPS_MAC_OPT_KIND && len == TCPS_MAC_OPT_LEN &&
		    opt[i + 2] == TCPS_MAC_MAGIC0 &&
		    opt[i + 3] == TCPS_MAC_MAGIC1) {
			if (tag)
				memcpy(tag, opt + i + 4, TCPS_MAC_TAG_SIZE);
			return 1;
		}
		i += len;
	}
	return 0;
}

struct tcps_saved_opts {
	int has_mss;
	uint16_t mss_val;
	int has_sack;
	int has_ws;
	uint8_t ws_val;
};

static void parse_saved_opts(struct tcphdr *th, struct tcps_saved_opts *so)
{
	int optlen = th->doff * 4 - sizeof(struct tcphdr);
	uint8_t *opt = (uint8_t *)th + sizeof(struct tcphdr);
	int i = 0;
	int len;

	memset(so, 0, sizeof(*so));
	while (i < optlen) {
		if (opt[i] == 0)
			break;
		if (opt[i] == 1) {
			i++;
			continue;
		}
		if (i + 1 >= optlen)
			break;
		len = opt[i + 1];
		if (len < 2)
			break;
		if (opt[i] == 2 && len == 4) {
			so->has_mss = 1;
			so->mss_val = ((uint16_t)opt[i + 2] << 8) | opt[i + 3];
		} else if (opt[i] == 3 && len == 3) {
			so->has_ws = 1;
			so->ws_val = opt[i + 2];
		} else if (opt[i] == 4 && len == 2) {
			so->has_sack = 1;
		}
		i += len;
	}
}

static int add_tcps_option(struct sk_buff *skb, const uint8_t pubkey[TCPS_DH_SIZE])
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	struct tcps_saved_opts so;
	int preserved_len;
	int new_opt_len;
	int old_hdr_len;
	int new_hdr_len;
	int diff;
	int new_doff;
	int tcplen;
	uint8_t *new_opt;
	int off;

	parse_saved_opts(th, &so);

	preserved_len = 0;
	if (so.has_mss)
		preserved_len = 4;
	else if (so.has_sack)
		preserved_len = 2;
	else if (so.has_ws)
		preserved_len = 3;

	new_opt_len = preserved_len + TCPS_OPT_LEN;
	while (new_opt_len % 4)
		new_opt_len++;

	old_hdr_len = th->doff * 4;
	new_hdr_len = sizeof(struct tcphdr) + new_opt_len;
	if (new_hdr_len > 60)
		return -ENOSPC;

	diff = new_hdr_len - old_hdr_len;
	new_doff = new_hdr_len / 4;

	if (diff > 0) {
		if (skb_tailroom(skb) < diff) {
			if (pskb_expand_head(skb, 0,
					     diff - skb_tailroom(skb),
					     GFP_ATOMIC))
				return -ENOMEM;
			iph = ip_hdr(skb);
			th = tcp_hdr(skb);
		}
		skb_put(skb, diff);
	} else if (diff < 0) {
		skb_trim(skb, skb->len + diff);
	}

	if (skb_ensure_writable(skb, skb->len))
		return -ENOMEM;
	iph = ip_hdr(skb);
	th = tcp_hdr(skb);

	new_opt = (uint8_t *)th + sizeof(struct tcphdr);
	off = 0;

	if (so.has_mss) {
		uint16_t mss = so.mss_val;
		if (mss > TCPS_MAC_OPT_LEN)
			mss -= TCPS_MAC_OPT_LEN;
		new_opt[off++] = 2;
		new_opt[off++] = 4;
		new_opt[off++] = (mss >> 8) & 0xFF;
		new_opt[off++] = mss & 0xFF;
	} else if (so.has_sack) {
		new_opt[off++] = 4;
		new_opt[off++] = 2;
	} else if (so.has_ws) {
		new_opt[off++] = 3;
		new_opt[off++] = 3;
		new_opt[off++] = so.ws_val;
	}

	new_opt[off++] = TCPS_OPT_KIND;
	new_opt[off++] = TCPS_OPT_LEN;
	new_opt[off++] = TCPS_OPT_MAGIC0;
	new_opt[off++] = TCPS_OPT_MAGIC1;
	memcpy(new_opt + off, pubkey, TCPS_DH_SIZE);
	off += TCPS_DH_SIZE;

	while (off < new_opt_len)
		new_opt[off++] = 1;

	th->doff = new_doff;
	iph->tot_len = htons(ntohs(iph->tot_len) + diff);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	th->check = 0;
	th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				      tcplen, IPPROTO_TCP,
				      csum_partial(th, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static int add_mac_option(struct sk_buff *skb, const uint8_t tag[TCPS_MAC_TAG_SIZE])
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int old_hdr_len = th->doff * 4;
	int new_hdr_len = old_hdr_len + TCPS_MAC_OPT_LEN;
	int diff = TCPS_MAC_OPT_LEN;
	int new_doff;
	int tcplen;
	int payload_len;
	uint8_t *opt;
	int off;

	if (new_hdr_len > 60)
		return -ENOSPC;

	new_doff = new_hdr_len / 4;

	if (skb_tailroom(skb) < diff) {
		if (pskb_expand_head(skb, 0,
				     diff - skb_tailroom(skb),
				     GFP_ATOMIC))
			return -ENOMEM;
		iph = ip_hdr(skb);
		th = tcp_hdr(skb);
	}
	skb_put(skb, diff);

	if (skb_ensure_writable(skb, skb->len))
		return -ENOMEM;
	iph = ip_hdr(skb);
	th = tcp_hdr(skb);

	tcplen = ntohs(iph->tot_len) + diff - iph->ihl * 4;
	payload_len = tcplen - old_hdr_len;
	if (payload_len > 0)
		memmove((uint8_t *)th + new_hdr_len,
			(uint8_t *)th + old_hdr_len, payload_len);

	opt = (uint8_t *)th + old_hdr_len;
	off = 0;

	opt[off++] = TCPS_MAC_OPT_KIND;
	opt[off++] = TCPS_MAC_OPT_LEN;
	opt[off++] = TCPS_MAC_MAGIC0;
	opt[off++] = TCPS_MAC_MAGIC1;
	memcpy(opt + off, tag, TCPS_MAC_TAG_SIZE);
	off += TCPS_MAC_TAG_SIZE;

	th->doff = new_doff;
	iph->tot_len = htons(ntohs(iph->tot_len) + diff);
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	th->check = 0;
	th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				      tcplen, IPPROTO_TCP,
				      csum_partial(th, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE;
	return 0;
}

static void tcps_conn_derive(struct tcps_conn *c)
{
	uint8_t shared[TCPS_DH_SIZE];
	uint8_t key_c2s[TCPS_KEY_SIZE];
	uint8_t key_s2c[TCPS_KEY_SIZE];
	uint8_t mac_c2s[TCPS_KEY_SIZE];
	uint8_t mac_s2c[TCPS_KEY_SIZE];

	if (tcps_dh_shared(c->dh_priv, c->dh_peer_pub, shared) < 0) {
		c->state = TCPS_DEAD;
		pr_warn("tcps: ECDH shared secret invalid, aborting session\n");
		return;
	}

	tcps_derive_session_keys(shared, c->client_isn, c->server_isn,
				 key_c2s, key_s2c, mac_c2s, mac_s2c);

	if (c->is_client) {
		memcpy(c->enc_key, key_c2s, TCPS_KEY_SIZE);
		memcpy(c->dec_key, key_s2c, TCPS_KEY_SIZE);
		memcpy(c->mac_enc_key, mac_c2s, TCPS_KEY_SIZE);
		memcpy(c->mac_dec_key, mac_s2c, TCPS_KEY_SIZE);
	} else {
		memcpy(c->enc_key, key_s2c, TCPS_KEY_SIZE);
		memcpy(c->dec_key, key_c2s, TCPS_KEY_SIZE);
		memcpy(c->mac_enc_key, mac_s2c, TCPS_KEY_SIZE);
		memcpy(c->mac_dec_key, mac_c2s, TCPS_KEY_SIZE);
	}

	memzero_explicit(shared, sizeof(shared));
	memzero_explicit(key_c2s, sizeof(key_c2s));
	memzero_explicit(key_s2c, sizeof(key_s2c));
	memzero_explicit(mac_c2s, sizeof(mac_c2s));
	memzero_explicit(mac_s2c, sizeof(mac_s2c));
	memzero_explicit(c->dh_priv, sizeof(c->dh_priv));
	memzero_explicit(c->dh_pub, sizeof(c->dh_pub));
	memzero_explicit(c->dh_peer_pub, sizeof(c->dh_peer_pub));

	c->state = TCPS_ENCRYPTED;

	pr_info("tcps: encrypted session %pI4:%u <-> %pI4:%u (ECDH+AEAD)\n",
		&c->saddr, ntohs(c->sport), &c->daddr, ntohs(c->dport));
}

static inline int tcps_skb_is_fragment(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	return ntohs(iph->frag_off) & (IP_MF | IP_OFFSET);
}

static unsigned int tcps_out(void *priv, struct sk_buff *skb,
			     const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	struct tcps_conn *c;
	int tcplen, payload_off, payload_len;
	uint64_t pos;
	uint8_t *payload;
	uint8_t tag[TCPS_MAC_TAG_SIZE];

	if (!skb || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	if (tcps_skb_is_fragment(skb))
		return NF_ACCEPT;
	if (skb_ensure_writable(skb, skb->len))
		return NF_ACCEPT;
	th = tcp_hdr(skb);

	rcu_read_lock();

	if (th->syn && !th->ack) {
		c = tcps_conn_add(iph->saddr, th->source,
				  iph->daddr, th->dest);
		if (c) {
			spin_lock(&c->lock);
			if (c->state != TCPS_NONE && c->state != TCPS_SYN_SENT) {
				pr_debug("tcps: SYN out state=%d, skip\n", c->state);
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_ACCEPT;
			}
			c->is_client = 1;
			c->client_isn = ntohl(th->seq);
			c->state = TCPS_SYN_SENT;
			c->last_active = jiffies;
			if (add_tcps_option(skb, c->dh_pub) < 0) {
				pr_warn("tcps: failed to add option to SYN %pI4:%u->%pI4:%u\n",
					&iph->saddr, ntohs(th->source),
					&iph->daddr, ntohs(th->dest));
				c->state = TCPS_DEAD;
			} else {
				pr_info("tcps: SYN out %pI4:%u->%pI4:%u isn=%u\n",
					&iph->saddr, ntohs(th->source),
					&iph->daddr, ntohs(th->dest),
					c->client_isn);
			}
			spin_unlock(&c->lock);
		} else {
			pr_debug("tcps: SYN out conn_add failed\n");
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->syn && th->ack) {
		c = tcps_conn_find_any(iph->saddr, th->source,
				       iph->daddr, th->dest);
		if (c && c->state == TCPS_SYN_RECV) {
			spin_lock(&c->lock);
			if (add_tcps_option(skb, c->dh_pub) < 0) {
				pr_warn("tcps: failed to add option to SYN+ACK %pI4:%u->%pI4:%u\n",
					&iph->saddr, ntohs(th->source),
					&iph->daddr, ntohs(th->dest));
				c->state = TCPS_DEAD;
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_ACCEPT;
			}
			c->server_isn = ntohl(th->seq);
			c->last_active = jiffies;
			tcps_conn_derive(c);
			pr_info("tcps: SYN+ACK out %pI4:%u->%pI4:%u isn=%u\n",
				&iph->saddr, ntohs(th->source),
				&iph->daddr, ntohs(th->dest),
				c->server_isn);
			spin_unlock(&c->lock);
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	c = tcps_conn_find_any(iph->saddr, th->source,
			       iph->daddr, th->dest);
	if (!c) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	spin_lock(&c->lock);
	if (c->state != TCPS_ENCRYPTED) {
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	c->last_active = jiffies;

	if (th->rst) {
		c->state = TCPS_DEAD;
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	payload_off = th->doff * 4;
	payload_len = tcplen - payload_off;
	if (payload_len < 0)
		payload_len = 0;

	if (payload_len > 0) {
		tcps_update_send_wrap(c, ntohl(th->seq));
		pos = tcps_send_pos(c, ntohl(th->seq));
		payload = (uint8_t *)th + payload_off;
		chacha20_xor_stream(c->enc_key, pos, payload, payload_len);
		tcps_compute_mac(c->mac_enc_key, pos,
				 payload, payload_len, tag);
		if (add_mac_option(skb, tag) < 0) {
			pr_warn("tcps: failed to add MAC option, dropping\n");
			spin_unlock(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		th = tcp_hdr(skb);
	}

	if (th->fin) {
		c->fin_out = 1;
		if (c->fin_in)
			c->state = TCPS_DEAD;
	}

	spin_unlock(&c->lock);
	rcu_read_unlock();
	return NF_ACCEPT;
}

static unsigned int tcps_in(void *priv, struct sk_buff *skb,
			    const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *th;
	struct tcps_conn *c;
	int tcplen, payload_off, payload_len;
	uint64_t pos;
	uint8_t *payload;
	uint8_t peer_pub[TCPS_DH_SIZE];
	uint8_t recv_tag[TCPS_MAC_TAG_SIZE];
	uint8_t calc_tag[TCPS_MAC_TAG_SIZE];
	if (!skb || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	if (tcps_skb_is_fragment(skb))
		return NF_ACCEPT;
	if (skb_ensure_writable(skb, skb->len))
		return NF_ACCEPT;
	th = tcp_hdr(skb);

	rcu_read_lock();

	if (th->syn && !th->ack) {
		if (tcp_option_find_tcps(th, peer_pub)) {
			c = tcps_conn_add(iph->saddr, th->source,
					  iph->daddr, th->dest);
			if (c) {
				spin_lock(&c->lock);
				if (c->state != TCPS_NONE &&
				    c->state != TCPS_SYN_RECV) {
					pr_debug("tcps: SYN in state=%d, skip\n", c->state);
					spin_unlock(&c->lock);
					rcu_read_unlock();
					return NF_ACCEPT;
				}
				c->is_client = 0;
				c->client_isn = ntohl(th->seq);
				c->last_active = jiffies;
				memcpy(c->dh_peer_pub, peer_pub,
				       TCPS_DH_SIZE);
				c->state = TCPS_SYN_RECV;
				pr_info("tcps: SYN in %pI4:%u->%pI4:%u isn=%u\n",
					&iph->saddr, ntohs(th->source),
					&iph->daddr, ntohs(th->dest),
					c->client_isn);
				spin_unlock(&c->lock);
			}
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->syn && th->ack) {
		c = tcps_conn_find_any(iph->saddr, th->source,
				       iph->daddr, th->dest);
		if (c && c->state == TCPS_SYN_SENT) {
			spin_lock(&c->lock);
			if (tcp_option_find_tcps(th, peer_pub)) {
				c->server_isn = ntohl(th->seq);
				c->last_active = jiffies;
				memcpy(c->dh_peer_pub, peer_pub,
				       TCPS_DH_SIZE);
				tcps_conn_derive(c);
				pr_info("tcps: SYN+ACK in %pI4:%u->%pI4:%u derived\n",
					&iph->saddr, ntohs(th->source),
					&iph->daddr, ntohs(th->dest));
			} else {
				pr_warn("tcps: SYN+ACK in no TCPS option, dead\n");
				c->state = TCPS_DEAD;
			}
			spin_unlock(&c->lock);
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	c = tcps_conn_find_any(iph->saddr, th->source,
			       iph->daddr, th->dest);
	if (!c) {
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	spin_lock(&c->lock);
	if (c->state != TCPS_ENCRYPTED) {
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	c->last_active = jiffies;

	if (th->rst) {
		c->state = TCPS_DEAD;
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	payload_off = th->doff * 4;
	payload_len = tcplen - payload_off;
	if (payload_len < 0)
		payload_len = 0;

	if (payload_len > 0) {
		if (!tcp_option_find_mac(th, recv_tag)) {
			pr_warn("tcps: no MAC option, dropping\n");
			spin_unlock(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		tcps_update_recv_wrap(c, ntohl(th->seq));
		pos = tcps_recv_pos(c, ntohl(th->seq));
		payload = (uint8_t *)th + payload_off;
		tcps_compute_mac(c->mac_dec_key, pos,
				 payload, payload_len, calc_tag);

		if (crypto_memneq(recv_tag, calc_tag, TCPS_MAC_TAG_SIZE)) {
			pr_warn("tcps: MAC verification failed, dropping\n");
			spin_unlock(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		chacha20_xor_stream(c->dec_key, pos, payload, payload_len);
		th->check = 0;
		th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
					      tcplen, IPPROTO_TCP,
					      csum_partial(th, tcplen, 0));
		skb->ip_summed = CHECKSUM_NONE;
	}

	if (th->fin) {
		c->fin_in = 1;
		if (c->fin_out)
			c->state = TCPS_DEAD;
	}

	spin_unlock(&c->lock);
	rcu_read_unlock();
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
		.priority = NF_IP_PRI_CONNTRACK_DEFRAG + 1,
	},
};

static int __init tcps_init(void)
{
	int err = nf_register_net_hooks(&init_net, tcps_ops, ARRAY_SIZE(tcps_ops));
	if (err) {
		pr_err("tcps: failed to register hooks\n");
		return err;
	}
	schedule_delayed_work(&tcps_gc_work, TCPS_GC_INTERVAL);
	pr_info("tcps: module loaded, ECDH (X25519) + ChaCha20-Poly1305 active\n");
	return 0;
}

static void __exit tcps_exit(void)
{
	cancel_delayed_work_sync(&tcps_gc_work);
	nf_unregister_net_hooks(&init_net, tcps_ops, ARRAY_SIZE(tcps_ops));
	tcps_conn_cleanup();
	pr_info("tcps: module unloaded\n");
}

module_init(tcps_init);
module_exit(tcps_exit);
