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
#include <linux/atomic.h>
#include <net/checksum.h>
#include <crypto/algapi.h>
#include "tcps.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tcps");
MODULE_DESCRIPTION("Transparent TCP encryption: ECDH + ChaCha20-Poly1305 + TOFU/MITM protection + forward secrecy");
MODULE_SOFTDEP("pre: libcurve25519");

static DEFINE_HASHTABLE(tcps_table, TCPS_HASH_BITS);
static DEFINE_SPINLOCK(tcps_lock);

static uint8_t tcps_static_priv[TCPS_DH_SIZE];
static uint8_t tcps_static_pub[TCPS_DH_SIZE];
static uint32_t tcps_epoch;
static DEFINE_HASHTABLE(tcps_peers_table, TCPS_PEER_HASH_BITS);
static DEFINE_SPINLOCK(tcps_peers_lock);

static int tcps_tofu_enforce = 1;
module_param_named(tofu_enforce, tcps_tofu_enforce, int, 0644);
MODULE_PARM_DESC(tofu_enforce, "TOFU enforcement: 0=off, 1=drop on key mismatch (default)");

static int tcps_enforce;
module_param_named(enforce, tcps_enforce, int, 0644);
MODULE_PARM_DESC(enforce, "Enforce encryption: 0=allow plaintext fallback, 1=drop non-TCPS connections (default: 0)");

static int tcps_auto_rotate = 1;
module_param_named(auto_rotate, tcps_auto_rotate, int, 0644);
MODULE_PARM_DESC(auto_rotate, "Auto-accept key rotation on epoch change: 0=reject, 1=accept (default: 1)");

#define TCPS_MAX_CONN 4096

static atomic_t tcps_conn_count = ATOMIC_INIT(0);

static void tcps_gc(struct work_struct *work);
static DECLARE_DELAYED_WORK(tcps_gc_work, tcps_gc);

static void tcps_conn_free_rcu(struct rcu_head *head);
static void tcps_compute_auth_tag(const uint8_t shared_static[TCPS_DH_SIZE],
				  uint32_t client_isn, uint32_t server_isn,
				  int is_client,
				  uint8_t tag[TCPS_AUTH_TAG_SIZE]);
static void tcps_compute_send_auth_tag(struct tcps_conn *c,
				       uint8_t auth_tag[TCPS_AUTH_TAG_SIZE]);

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
	uint32_t offset = seq - isn - 1;
	uint64_t pos = ((uint64_t)c->send_wrap << 32) + offset;

	if (c->max_send_pos > 0 && pos + (1ULL << 31) < c->max_send_pos) {
		c->send_wrap++;
		pos += (1ULL << 32);
	}
	if (pos > c->max_send_pos)
		c->max_send_pos = pos;

	return pos;
}

static inline uint64_t tcps_recv_pos(struct tcps_conn *c, uint32_t seq)
{
	uint32_t isn = c->is_client ? c->server_isn : c->client_isn;
	uint32_t offset = seq - isn - 1;
	uint64_t pos = ((uint64_t)c->recv_wrap << 32) + offset;

	if (c->max_recv_pos > 0 && pos + (1ULL << 31) < c->max_recv_pos) {
		c->recv_wrap++;
		pos += (1ULL << 32);
	}
	if (pos > c->max_recv_pos)
		c->max_recv_pos = pos;

	return pos;
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
	uint8_t dh_priv[TCPS_DH_SIZE];
	uint8_t dh_pub[TCPS_DH_SIZE];

	tcps_dh_keygen(dh_priv, dh_pub);

	if (atomic_read(&tcps_conn_count) >= TCPS_MAX_CONN) {
		memzero_explicit(dh_priv, sizeof(dh_priv));
		memzero_explicit(dh_pub, sizeof(dh_pub));
		return NULL;
	}

	h = tcps_hash4(saddr, sport, daddr, dport);
	spin_lock(&tcps_lock);
	hash_for_each_possible(tcps_table, c, hnode, h) {
		if ((c->saddr == saddr && c->daddr == daddr &&
		     c->sport == sport && c->dport == dport) ||
		    (c->saddr == daddr && c->daddr == saddr &&
		     c->sport == dport && c->dport == sport)) {
			if (c->state == TCPS_DEAD) {
				hash_del_rcu(&c->hnode);
				atomic_dec(&tcps_conn_count);
				call_rcu(&c->rcu, tcps_conn_free_rcu);
				break;
			}
			spin_unlock(&tcps_lock);
			memzero_explicit(dh_priv, sizeof(dh_priv));
			memzero_explicit(dh_pub, sizeof(dh_pub));
			return c;
		}
	}
	c = kzalloc(sizeof(*c), GFP_ATOMIC);
	if (!c) {
		spin_unlock(&tcps_lock);
		memzero_explicit(dh_priv, sizeof(dh_priv));
		memzero_explicit(dh_pub, sizeof(dh_pub));
		return NULL;
	}
	c->saddr = saddr;
	c->daddr = daddr;
	c->sport = sport;
	c->dport = dport;
	c->last_active = jiffies;
	spin_lock_init(&c->lock);
	memcpy(c->dh_priv, dh_priv, TCPS_DH_SIZE);
	memcpy(c->dh_pub, dh_pub, TCPS_DH_SIZE);
	memzero_explicit(dh_priv, sizeof(dh_priv));
	memzero_explicit(dh_pub, sizeof(dh_pub));
	atomic_inc(&tcps_conn_count);
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

void tcps_conn_cleanup(void)
{
	struct tcps_conn *c;
	struct hlist_node *tmp;
	unsigned bkt;
	hash_for_each_safe(tcps_table, bkt, tmp, c, hnode) {
		hash_del(&c->hnode);
		atomic_dec(&tcps_conn_count);
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
		else if (c->state == TCPS_ENCRYPTED && !c->ti_recv &&
			 time_after(now, c->last_active + TCPS_TI_TIMEOUT)) {
			pr_warn("tcps: TI timeout for %pI4:%u <-> %pI4:%u, dropping\n",
				&c->saddr, ntohs(c->sport),
				&c->daddr, ntohs(c->dport));
			del = 1;
		}
		else if (c->state == TCPS_PLAIN_PROBE &&
			 time_after(now, c->last_active + TCPS_PROBE_TIMEOUT)) {
			pr_info("tcps: probe timeout for %pI4:%u <-> %pI4:%u, peer has no module\n",
				&c->saddr, ntohs(c->sport),
				&c->daddr, ntohs(c->dport));
			del = 1;
		}
		else if (time_after(now, c->last_active + TCPS_IDLE_TIMEOUT))
			del = 1;
		spin_unlock(&c->lock);
		if (del) {
			hash_del_rcu(&c->hnode);
			atomic_dec(&tcps_conn_count);
			call_rcu(&c->rcu, tcps_conn_free_rcu);
		}
	}
	spin_unlock(&tcps_lock);
	schedule_delayed_work(&tcps_gc_work, TCPS_GC_INTERVAL);
}

int tcps_tofu_verify(__be32 addr, const uint8_t pubkey[TCPS_DH_SIZE],
		     const uint8_t auth_tag[TCPS_AUTH_TAG_SIZE],
		     uint32_t client_isn, uint32_t server_isn,
		     int is_client, uint32_t peer_epoch)
{
	struct tcps_peer_entry *p, *new_p;
	uint32_t h = jhash_1word((__force u32)addr, 0);

	rcu_read_lock();
	hash_for_each_possible_rcu(tcps_peers_table, p, hnode, h) {
		if (p->addr == addr) {
			uint8_t saved_pub[TCPS_DH_SIZE];
			uint32_t saved_epoch;
			int mismatch;

			memcpy(saved_pub, p->pubkey, TCPS_DH_SIZE);
			saved_epoch = p->epoch;
			rcu_read_unlock();

			mismatch = crypto_memneq(saved_pub, pubkey, TCPS_DH_SIZE);
			if (!mismatch) {
				if (auth_tag) {
					uint8_t shared[TCPS_DH_SIZE];
					uint8_t expected[TCPS_AUTH_TAG_SIZE];

					if (tcps_dh_shared(tcps_static_priv, saved_pub,
							   shared) < 0) {
						memzero_explicit(shared, sizeof(shared));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						pr_warn("tcps: auth_tag DH failed for %pI4\n",
							&addr);
						return -1;
					}
					tcps_compute_auth_tag(shared, client_isn,
							      server_isn, is_client,
							      expected);
					memzero_explicit(shared, sizeof(shared));
					if (crypto_memneq(auth_tag, expected,
							  TCPS_AUTH_TAG_SIZE)) {
						memzero_explicit(expected, sizeof(expected));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						pr_warn("tcps: MITM detected! auth_tag mismatch for peer %pI4\n",
							&addr);
						return -1;
					}
					memzero_explicit(expected, sizeof(expected));
				}
				if (saved_epoch != peer_epoch) {
					spin_lock(&tcps_peers_lock);
					hash_for_each_possible(tcps_peers_table, p, hnode, h) {
						if (p->addr == addr) {
							p->epoch = peer_epoch;
							break;
						}
					}
					spin_unlock(&tcps_peers_lock);
				}
				memzero_explicit(saved_pub, sizeof(saved_pub));
				return 1;
			}

			if (peer_epoch != saved_epoch) {
				if (!tcps_auto_rotate) {
					pr_warn("tcps: key rotation rejected for peer %pI4 (auto_rotate=0, epoch %u -> %u)\n",
						&addr, saved_epoch, peer_epoch);
					memzero_explicit(saved_pub, sizeof(saved_pub));
					return -1;
				}
				pr_warn("tcps: key rotation detected for peer %pI4 (epoch %u -> %u)\n",
					&addr, saved_epoch, peer_epoch);
				pr_warn("tcps: old fingerprint %*phN, new fingerprint %*phN\n",
					8, saved_pub, 8, pubkey);

				if (auth_tag) {
					uint8_t shared[TCPS_DH_SIZE];
					uint8_t expected[TCPS_AUTH_TAG_SIZE];

					if (tcps_dh_shared(tcps_static_priv, pubkey,
							   shared) < 0) {
						memzero_explicit(shared, sizeof(shared));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						pr_warn("tcps: rotation auth_tag DH failed for %pI4\n",
							&addr);
						return -1;
					}
					tcps_compute_auth_tag(shared, client_isn,
							      server_isn, is_client,
							      expected);
					memzero_explicit(shared, sizeof(shared));
					if (crypto_memneq(auth_tag, expected,
							  TCPS_AUTH_TAG_SIZE)) {
						memzero_explicit(expected, sizeof(expected));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						pr_warn("tcps: rotation auth_tag mismatch for peer %pI4\n",
							&addr);
						return -1;
					}
					memzero_explicit(expected, sizeof(expected));
				}

				spin_lock(&tcps_peers_lock);
				hash_for_each_possible(tcps_peers_table, p, hnode, h) {
					if (p->addr == addr) {
						memcpy(p->pubkey, pubkey, TCPS_DH_SIZE);
						p->epoch = peer_epoch;
						break;
					}
				}
				spin_unlock(&tcps_peers_lock);

				memzero_explicit(saved_pub, sizeof(saved_pub));
				return 1;
			}

			pr_warn("tcps: MITM detected! Static key mismatch for peer %pI4 (same epoch %u)\n",
				&addr, saved_epoch);
			pr_warn("tcps: expected %*phN, got %*phN\n",
				8, saved_pub, 8, pubkey);
			memzero_explicit(saved_pub, sizeof(saved_pub));
			return -1;
		}
	}
	rcu_read_unlock();

	new_p = kzalloc(sizeof(*new_p), GFP_ATOMIC);
	if (!new_p)
		return -1;

	new_p->addr = addr;
	memcpy(new_p->pubkey, pubkey, TCPS_DH_SIZE);
	new_p->epoch = peer_epoch;

	spin_lock(&tcps_peers_lock);
	hash_for_each_possible(tcps_peers_table, p, hnode, h) {
		if (p->addr == addr) {
			uint8_t saved_pub[TCPS_DH_SIZE];
			uint32_t saved_epoch;
			int mismatch;

			memcpy(saved_pub, p->pubkey, TCPS_DH_SIZE);
			saved_epoch = p->epoch;
			spin_unlock(&tcps_peers_lock);
			kfree(new_p);
			mismatch = crypto_memneq(saved_pub, pubkey, TCPS_DH_SIZE);
			if (!mismatch) {
				if (auth_tag) {
					uint8_t shared[TCPS_DH_SIZE];
					uint8_t expected[TCPS_AUTH_TAG_SIZE];

					if (tcps_dh_shared(tcps_static_priv, saved_pub,
							   shared) < 0) {
						memzero_explicit(shared, sizeof(shared));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						return -1;
					}
					tcps_compute_auth_tag(shared, client_isn,
							      server_isn, is_client,
							      expected);
					memzero_explicit(shared, sizeof(shared));
					if (crypto_memneq(auth_tag, expected,
							  TCPS_AUTH_TAG_SIZE)) {
						memzero_explicit(expected, sizeof(expected));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						pr_warn("tcps: MITM detected! auth_tag mismatch for peer %pI4\n",
							&addr);
						return -1;
					}
					memzero_explicit(expected, sizeof(expected));
				}
				memzero_explicit(saved_pub, sizeof(saved_pub));
				return 1;
			}

			if (peer_epoch != saved_epoch) {
				if (!tcps_auto_rotate) {
					memzero_explicit(saved_pub, sizeof(saved_pub));
					pr_warn("tcps: key rotation rejected for peer %pI4 (auto_rotate=0)\n",
						&addr);
					return -1;
				}
				pr_warn("tcps: key rotation detected for peer %pI4 (epoch %u -> %u)\n",
					&addr, saved_epoch, peer_epoch);
				if (auth_tag) {
					uint8_t shared[TCPS_DH_SIZE];
					uint8_t expected[TCPS_AUTH_TAG_SIZE];

					if (tcps_dh_shared(tcps_static_priv, pubkey,
							   shared) < 0) {
						memzero_explicit(shared, sizeof(shared));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						return -1;
					}
					tcps_compute_auth_tag(shared, client_isn,
							      server_isn, is_client,
							      expected);
					memzero_explicit(shared, sizeof(shared));
					if (crypto_memneq(auth_tag, expected,
							  TCPS_AUTH_TAG_SIZE)) {
						memzero_explicit(expected, sizeof(expected));
						memzero_explicit(saved_pub, sizeof(saved_pub));
						return -1;
					}
					memzero_explicit(expected, sizeof(expected));
				}

				spin_lock(&tcps_peers_lock);
				hash_for_each_possible(tcps_peers_table, p, hnode, h) {
					if (p->addr == addr) {
						memcpy(p->pubkey, pubkey, TCPS_DH_SIZE);
						p->epoch = peer_epoch;
						break;
					}
				}
				spin_unlock(&tcps_peers_lock);

				memzero_explicit(saved_pub, sizeof(saved_pub));
				return 1;
			}

			memzero_explicit(saved_pub, sizeof(saved_pub));
			pr_warn("tcps: MITM detected! Static key mismatch for peer %pI4 (same epoch %u)\n",
				&addr, saved_epoch);
			return -1;
		}
	}
	hash_add_rcu(tcps_peers_table, &new_p->hnode, h);
	spin_unlock(&tcps_peers_lock);

	pr_info("tcps: TOFU: new peer %pI4 fingerprint %*phN epoch %u\n",
		&addr, 8, pubkey, peer_epoch);
	return 0;
}

void tcps_tofu_cleanup(void)
{
	struct tcps_peer_entry *p;
	struct hlist_node *tmp;
	unsigned bkt;

	hash_for_each_safe(tcps_peers_table, bkt, tmp, p, hnode) {
		hash_del(&p->hnode);
		memzero_explicit(p->pubkey, sizeof(p->pubkey));
		kfree(p);
	}
}

static int tcp_option_find_tcps(struct tcphdr *th,
				uint8_t peer_pub[TCPS_DH_SIZE],
				uint32_t *peer_epoch)
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
			if (peer_epoch)
				*peer_epoch = (opt[i + 4] << 24) |
					      (opt[i + 5] << 16) |
					      (opt[i + 6] << 8) |
					      opt[i + 7];
			if (peer_pub)
				memcpy(peer_pub, opt + i + 4 + TCPS_OPT_EPOCH_SIZE,
				       TCPS_DH_SIZE);
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

static int add_tcps_option(struct sk_buff *skb,
			   const uint8_t pubkey[TCPS_DH_SIZE],
			   uint32_t epoch)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int new_opt_len;
	int old_hdr_len;
	int new_hdr_len;
	int diff;
	int new_doff;
	int tcplen;
	uint8_t *new_opt;
	int off;

	new_opt_len = TCPS_OPT_LEN;
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

	new_opt[off++] = TCPS_OPT_KIND;
	new_opt[off++] = TCPS_OPT_LEN;
	new_opt[off++] = TCPS_OPT_MAGIC0;
	new_opt[off++] = TCPS_OPT_MAGIC1;
	new_opt[off++] = (epoch >> 24) & 0xFF;
	new_opt[off++] = (epoch >> 16) & 0xFF;
	new_opt[off++] = (epoch >> 8) & 0xFF;
	new_opt[off++] = epoch & 0xFF;
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

	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
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

static int tcp_option_find_ti(struct tcphdr *th,
			      uint8_t peer_static_pub[TCPS_DH_SIZE],
			      uint8_t auth_tag[TCPS_AUTH_TAG_SIZE])
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
		if (opt[i] == TCPS_TI_OPT_KIND && len == TCPS_TI_OPT_LEN &&
		    opt[i + 2] == TCPS_TI_MAGIC0 &&
		    opt[i + 3] == TCPS_TI_MAGIC1) {
			if (peer_static_pub)
				memcpy(peer_static_pub, opt + i + 4,
				       TCPS_DH_SIZE);
			if (auth_tag)
				memcpy(auth_tag, opt + i + 4 + TCPS_DH_SIZE,
				       TCPS_AUTH_TAG_SIZE);
			return 1;
		}
		i += len;
	}
	return 0;
}

static int add_ti_option(struct sk_buff *skb,
			 const uint8_t static_pub[TCPS_DH_SIZE],
			 const uint8_t auth_tag[TCPS_AUTH_TAG_SIZE])
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int new_hdr_len = sizeof(struct tcphdr) + TCPS_TI_OPT_LEN;
	int old_hdr_len = th->doff * 4;
	int diff = new_hdr_len - old_hdr_len;
	int new_doff = new_hdr_len / 4;
	int tcplen;
	uint8_t *opt;

	if (new_hdr_len > 60)
		return -ENOSPC;

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

	opt = (uint8_t *)th + sizeof(struct tcphdr);
	opt[0] = TCPS_TI_OPT_KIND;
	opt[1] = TCPS_TI_OPT_LEN;
	opt[2] = TCPS_TI_MAGIC0;
	opt[3] = TCPS_TI_MAGIC1;
	memcpy(opt + 4, static_pub, TCPS_DH_SIZE);
	memcpy(opt + 4 + TCPS_DH_SIZE, auth_tag, TCPS_AUTH_TAG_SIZE);

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

static void tcps_compute_auth_tag(const uint8_t shared_static[TCPS_DH_SIZE],
				  uint32_t client_isn, uint32_t server_isn,
				  int is_client,
				  uint8_t tag[TCPS_AUTH_TAG_SIZE])
{
	uint8_t input[16];
	uint64_t pos = (3ULL << 62) & ~15ULL;

	memset(input, 0, 16);
	input[0] = (uint8_t)(client_isn >> 24);
	input[1] = (uint8_t)(client_isn >> 16);
	input[2] = (uint8_t)(client_isn >> 8);
	input[3] = (uint8_t)(client_isn);
	input[4] = (uint8_t)(server_isn >> 24);
	input[5] = (uint8_t)(server_isn >> 16);
	input[6] = (uint8_t)(server_isn >> 8);
	input[7] = (uint8_t)(server_isn);
	input[8] = 'T';
	input[9] = 'A';
	input[10] = 'U';
	input[11] = 'T';
	input[12] = is_client ? 1 : 0;

	chacha20_xor_stream(shared_static, pos, input, 16);
	memcpy(tag, input, TCPS_AUTH_TAG_SIZE);
	memzero_explicit(input, sizeof(input));
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
		return NF_DROP;
	th = tcp_hdr(skb);

	rcu_read_lock();

	if (th->syn && !th->ack) {
		c = tcps_conn_add(iph->saddr, th->source,
				  iph->daddr, th->dest);
		if (c) {
			spin_lock(&c->lock);
			if (c->state != TCPS_NONE && c->state != TCPS_SYN_SENT) {
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_ACCEPT;
			}
			c->is_client = 1;
			c->client_isn = ntohl(th->seq);
			c->state = TCPS_SYN_SENT;
			c->last_active = jiffies;
			if (add_tcps_option(skb, c->dh_pub, tcps_epoch) < 0) {
				pr_warn("tcps: failed to add option to SYN %pI4:%u->%pI4:%u, dropping\n",
					&iph->saddr, ntohs(th->source),
					&iph->daddr, ntohs(th->dest));
				c->state = TCPS_DEAD;
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_DROP;
			}
			spin_unlock(&c->lock);
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->syn && th->ack) {
		c = tcps_conn_find_any(iph->saddr, th->source,
				       iph->daddr, th->dest);
		if (c && c->state == TCPS_SYN_RECV) {
			spin_lock(&c->lock);
			if (add_tcps_option(skb, c->dh_pub, tcps_epoch) < 0) {
				pr_warn("tcps: failed to add option to SYN+ACK %pI4:%u->%pI4:%u, dropping\n",
					&iph->saddr, ntohs(th->source),
					&iph->daddr, ntohs(th->dest));
				c->state = TCPS_DEAD;
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_DROP;
			}
			c->server_isn = ntohl(th->seq);
			c->last_active = jiffies;
			tcps_conn_derive(c);
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

	if (c->kill) {
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_DROP;
	}

	if (c->state == TCPS_PLAIN_PROBE) {
		tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
		payload_off = th->doff * 4;
		payload_len = tcplen - payload_off;
		if (payload_len < 0)
			payload_len = 0;

		if (!c->probe_sent && payload_len > 0) {
			uint8_t probe[TCPS_PROBE_SIZE];

			if (c->is_client) {
				probe[0] = TCPS_PROBE_REQ_MARKER;
				probe[1] = TCPS_PROBE_MAGIC1;
				probe[2] = TCPS_PROBE_MAGIC2;
				probe[3] = TCPS_PROBE_REQ_MAGIC3;
				memcpy(probe + 4, tcps_static_pub,
				       TCPS_DH_SIZE);
			} else if (c->probe_recv) {
				probe[0] = TCPS_PROBE_RSP_MARKER;
				probe[1] = TCPS_PROBE_MAGIC1;
				probe[2] = TCPS_PROBE_MAGIC2;
				probe[3] = TCPS_PROBE_RSP_MAGIC3;
				memcpy(probe + 4, tcps_static_pub,
				       TCPS_DH_SIZE);
			} else {
				if (th->fin)
					c->fin_out = 1;
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_ACCEPT;
			}

			if (skb_tailroom(skb) < TCPS_PROBE_SIZE) {
				if (pskb_expand_head(skb, 0,
					 TCPS_PROBE_SIZE -
					 skb_tailroom(skb),
					 GFP_ATOMIC)) {
					spin_unlock(&c->lock);
					rcu_read_unlock();
					return NF_DROP;
				}
				iph = ip_hdr(skb);
				th = tcp_hdr(skb);
			}
			skb_put(skb, TCPS_PROBE_SIZE);
			if (skb_ensure_writable(skb, skb->len)) {
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			th = tcp_hdr(skb);

			payload = (uint8_t *)th + payload_off;
			memmove(payload + TCPS_PROBE_SIZE, payload,
				payload_len);
			memcpy(payload, probe, TCPS_PROBE_SIZE);

			iph->tot_len = htons(ntohs(iph->tot_len) +
					     TCPS_PROBE_SIZE);
			iph->check = 0;
			iph->check = ip_fast_csum((unsigned char *)iph,
						  iph->ihl);
			{
				int tl = ntohs(iph->tot_len) -
					 iph->ihl * 4;
				th->check = 0;
				th->check = csum_tcpudp_magic(
					iph->saddr, iph->daddr,
					tl, IPPROTO_TCP,
					csum_partial(th, tl, 0));
				skb->ip_summed = CHECKSUM_NONE;
			}

			c->probe_sent = 1;
			pr_info("tcps: probe %s %pI4:%u <-> %pI4:%u\n",
				c->is_client ? "sent" : "response sent",
				&c->saddr, ntohs(c->sport),
				&c->daddr, ntohs(c->dport));
		}

		if (th->fin)
			c->fin_out = 1;

		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (c->state != TCPS_ENCRYPTED && c->state != TCPS_AUTHENTICATED) {
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

	if (c->state == TCPS_ENCRYPTED && !c->ti_recv &&
	    !th->syn && !th->fin && payload_len == 0) {
		uint8_t auth_tag[TCPS_AUTH_TAG_SIZE];

		tcps_compute_send_auth_tag(c, auth_tag);

		if (add_ti_option(skb, tcps_static_pub, auth_tag) != 0) {
			pr_warn("tcps: failed to add TI option, dropping\n");
			memzero_explicit(auth_tag, sizeof(auth_tag));
			spin_unlock(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}
		c->ti_sent = 1;
		pr_info("tcps: TI option sent %pI4:%u <-> %pI4:%u\n",
			&c->saddr, ntohs(c->sport),
			&c->daddr, ntohs(c->dport));
		memzero_explicit(auth_tag, sizeof(auth_tag));
		iph = ip_hdr(skb);
		th = tcp_hdr(skb);
	}

	if (payload_len > 0 || th->fin) {
		uint8_t tcp_flags = ((uint8_t *)th)[13];
		int embed_ti = (c->state == TCPS_ENCRYPTED && !c->ti_sent &&
				payload_len > 0);
		uint8_t ti_prefix[TCPS_TI_EMBED_SIZE];
		int ti_prefix_len = 0;

		if (embed_ti) {
			uint8_t auth_tag[TCPS_AUTH_TAG_SIZE];

			tcps_compute_send_auth_tag(c, auth_tag);

			ti_prefix[0] = TCPS_TI_EMBED_MARKER;
			memcpy(ti_prefix + 1, tcps_static_pub, TCPS_DH_SIZE);
			memcpy(ti_prefix + 1 + TCPS_DH_SIZE, auth_tag,
			       TCPS_AUTH_TAG_SIZE);
			memzero_explicit(auth_tag, sizeof(auth_tag));
			ti_prefix_len = TCPS_TI_EMBED_SIZE;
		}

		if (embed_ti) {
			if (skb_tailroom(skb) < TCPS_TI_EMBED_SIZE) {
				if (pskb_expand_head(skb, 0,
						TCPS_TI_EMBED_SIZE -
						skb_tailroom(skb),
						GFP_ATOMIC)) {
					memzero_explicit(ti_prefix,
							 sizeof(ti_prefix));
					spin_unlock(&c->lock);
					rcu_read_unlock();
					return NF_DROP;
				}
				iph = ip_hdr(skb);
				th = tcp_hdr(skb);
			}
			skb_put(skb, TCPS_TI_EMBED_SIZE);
			if (skb_ensure_writable(skb, skb->len)) {
				memzero_explicit(ti_prefix, sizeof(ti_prefix));
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			th = tcp_hdr(skb);

			payload = (uint8_t *)th + payload_off;
			memmove(payload + TCPS_TI_EMBED_SIZE, payload,
				payload_len);
			memcpy(payload, ti_prefix, TCPS_TI_EMBED_SIZE);

			iph->tot_len = htons(ntohs(iph->tot_len) +
					     TCPS_TI_EMBED_SIZE);
			iph->check = 0;
			iph->check = ip_fast_csum((unsigned char *)iph,
						  iph->ihl);
			{
				int tl = ntohs(iph->tot_len) - iph->ihl * 4;
				th->check = 0;
				th->check = csum_tcpudp_magic(
					iph->saddr, iph->daddr,
					tl, IPPROTO_TCP,
					csum_partial(th, tl, 0));
				skb->ip_summed = CHECKSUM_NONE;
			}
		}

		pos = tcps_send_pos(c, ntohl(th->seq));

		if (payload_len > 0) {
			payload = (uint8_t *)th + payload_off + ti_prefix_len;
			chacha20_xor_stream(c->enc_key, pos, payload,
					    payload_len);
		}

		if (ti_prefix_len > 0) {
			tcps_compute_mac_prefix(c->mac_enc_key, pos, tcp_flags,
						ti_prefix, ti_prefix_len,
						(uint8_t *)th + payload_off +
						ti_prefix_len,
						payload_len, tag);
		} else {
			tcps_compute_mac(c->mac_enc_key, pos, tcp_flags,
					 payload_len > 0 ?
						(uint8_t *)th + payload_off :
						NULL,
					 payload_len, tag);
		}
		memzero_explicit(ti_prefix, sizeof(ti_prefix));

		if (add_mac_option(skb, tag) < 0) {
			pr_warn("tcps: failed to add MAC option, dropping\n");
			spin_unlock(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		if (embed_ti) {
			c->ti_sent = 1;
			pr_info("tcps: TI embedded in data %pI4:%u <-> %pI4:%u\n",
				&c->saddr, ntohs(c->sport),
				&c->daddr, ntohs(c->dport));
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

static int tcps_tofu_peer_exists(__be32 addr)
{
	struct tcps_peer_entry *p;
	uint32_t h = jhash_1word((__force u32)addr, 0);

	rcu_read_lock();
	hash_for_each_possible_rcu(tcps_peers_table, p, hnode, h) {
		if (p->addr == addr) {
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
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
	uint8_t ti_pub[TCPS_DH_SIZE];
	uint8_t ti_tag[TCPS_AUTH_TAG_SIZE];
	uint32_t peer_epoch;

	if (!skb || skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;
	if (tcps_skb_is_fragment(skb))
		return NF_ACCEPT;
	if (skb_ensure_writable(skb, skb->len))
		return NF_DROP;
	th = tcp_hdr(skb);

	rcu_read_lock();

	if (th->syn && !th->ack) {
		if (tcp_option_find_tcps(th, peer_pub, &peer_epoch)) {
			c = tcps_conn_add(iph->saddr, th->source,
					  iph->daddr, th->dest);
			if (c) {
				spin_lock(&c->lock);
				if (c->state != TCPS_NONE &&
				    c->state != TCPS_SYN_RECV) {
					spin_unlock(&c->lock);
					rcu_read_unlock();
					return NF_ACCEPT;
				}
				c->is_client = 0;
				c->client_isn = ntohl(th->seq);
				c->last_active = jiffies;
				c->peer_epoch = peer_epoch;
				memcpy(c->dh_peer_pub, peer_pub,
				       TCPS_DH_SIZE);
				c->state = TCPS_SYN_RECV;
				spin_unlock(&c->lock);
			}
		} else {
			if (tcps_tofu_peer_exists(iph->saddr)) {
				pr_warn("tcps: downgrade detected! SYN without TCPS from known peer %pI4\n",
					&iph->saddr);
				rcu_read_unlock();
				return NF_DROP;
			}
			if (tcps_enforce) {
				rcu_read_unlock();
				return NF_DROP;
			}
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->syn && th->ack) {
		int drop = 0;
		c = tcps_conn_find_any(iph->saddr, th->source,
				       iph->daddr, th->dest);
		if (c && c->state == TCPS_SYN_SENT) {
			spin_lock(&c->lock);
			if (tcp_option_find_tcps(th, peer_pub, &peer_epoch)) {
				c->server_isn = ntohl(th->seq);
				c->last_active = jiffies;
				c->peer_epoch = peer_epoch;
				memcpy(c->dh_peer_pub, peer_pub,
				       TCPS_DH_SIZE);
				tcps_conn_derive(c);
			} else {
				__be32 peer_addr = c->is_client ? c->daddr : c->saddr;
				if (tcps_tofu_peer_exists(peer_addr)) {
					pr_warn("tcps: downgrade detected! SYN+ACK without TCPS from known peer %pI4\n",
						&peer_addr);
					c->state = TCPS_DEAD;
					drop = 1;
				} else {
					c->server_isn = ntohl(th->seq);
					pr_info("tcps: peer %pI4 has no TCPS module, probing\n",
						&peer_addr);
					c->state = TCPS_PLAIN_PROBE;
					drop = 0;
				}
			}
			spin_unlock(&c->lock);
		}
		rcu_read_unlock();
		return drop ? NF_DROP : NF_ACCEPT;
	}

	c = tcps_conn_find_any(iph->saddr, th->source,
			       iph->daddr, th->dest);
	if (!c) {
		if (!th->syn && !th->rst && !th->fin) {
			tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
			payload_off = th->doff * 4;
			payload_len = tcplen - payload_off;
			if (payload_len < 0)
				payload_len = 0;

			if (payload_len >= TCPS_PROBE_SIZE) {
				uint8_t *p = (uint8_t *)th + payload_off;
				if (p[0] == TCPS_PROBE_REQ_MARKER &&
				    p[1] == TCPS_PROBE_MAGIC1 &&
				    p[2] == TCPS_PROBE_MAGIC2 &&
				    p[3] == TCPS_PROBE_REQ_MAGIC3) {
					uint8_t client_pub[TCPS_DH_SIZE];
					uint8_t zero_tag[TCPS_AUTH_TAG_SIZE];

					memcpy(client_pub, p + 4,
					       TCPS_DH_SIZE);

					c = tcps_conn_add(iph->daddr, th->dest,
							  iph->saddr,
							  th->source);
					if (c) {
						spin_lock(&c->lock);
						c->is_client = 0;
						memcpy(c->dh_peer_pub,
						       client_pub,
						       TCPS_DH_SIZE);
						c->probe_recv = 1;
						c->state = TCPS_PLAIN_PROBE;
						c->last_active = jiffies;
						spin_unlock(&c->lock);
					}

					{
						int app_len = payload_len -
							      TCPS_PROBE_SIZE;
						if (app_len > 0) {
							memmove(
							 (uint8_t *)th +
							 payload_off,
							 (uint8_t *)th +
							 payload_off +
							 TCPS_PROBE_SIZE,
							 app_len);
						}
						skb_trim(skb,
							 skb->len -
							 TCPS_PROBE_SIZE);
						iph = ip_hdr(skb);
						th = tcp_hdr(skb);
						iph->tot_len = htons(
						 ntohs(iph->tot_len) -
						 TCPS_PROBE_SIZE);
						iph->check = 0;
						iph->check = ip_fast_csum(
						 (unsigned char *)iph,
						 iph->ihl);
						tcplen = ntohs(iph->tot_len) -
							 iph->ihl * 4;
						th->check = 0;
						th->check =
						 csum_tcpudp_magic(
						  iph->saddr, iph->daddr,
						  tcplen, IPPROTO_TCP,
						  csum_partial(th, tcplen,
							       0));
						skb->ip_summed =
							CHECKSUM_NONE;
					}

					memset(zero_tag, 0,
					       TCPS_AUTH_TAG_SIZE);
					tcps_tofu_verify(iph->saddr,
							 client_pub,
							 zero_tag, 0, 0,
							 0, 0);

					pr_warn("tcps: probe received from %pI4:%u — TCPS option was stripped, possible MITM\n",
						&iph->saddr,
						ntohs(th->source));
				}
			}
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	spin_lock(&c->lock);

	if (c->kill) {
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_DROP;
	}

	if (c->state == TCPS_PLAIN_PROBE) {
		c->last_active = jiffies;

		if (c->is_client && c->probe_sent && !c->probe_recv) {
			tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
			payload_off = th->doff * 4;
			payload_len = tcplen - payload_off;
			if (payload_len < 0)
				payload_len = 0;

			if (payload_len >= TCPS_PROBE_SIZE) {
				uint8_t *p = (uint8_t *)th + payload_off;
				if (p[0] == TCPS_PROBE_RSP_MARKER &&
				    p[1] == TCPS_PROBE_MAGIC1 &&
				    p[2] == TCPS_PROBE_MAGIC2 &&
				    p[3] == TCPS_PROBE_RSP_MAGIC3) {
					uint8_t server_pub[TCPS_DH_SIZE];
					uint8_t zero_tag[TCPS_AUTH_TAG_SIZE];

					memcpy(server_pub, p + 4,
					       TCPS_DH_SIZE);

					pr_warn("tcps: DOWNGRADE DETECTED! Peer %pI4 has TCPS module but option was stripped\n",
						&c->daddr);

					memset(zero_tag, 0,
					       TCPS_AUTH_TAG_SIZE);
					tcps_tofu_verify(c->daddr,
							 server_pub,
							 zero_tag, 0, 0,
							 1, 0);

					c->probe_recv = 1;
					c->kill = 1;
					c->state = TCPS_DEAD;

					spin_unlock(&c->lock);
					rcu_read_unlock();
					return NF_DROP;
				}
			}
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

	if (c->state != TCPS_ENCRYPTED && c->state != TCPS_AUTHENTICATED) {
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	c->last_active = jiffies;

	if (th->rst) {
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_DROP;
	}

	if (c->state == TCPS_ENCRYPTED && !c->ti_recv) {
		if (tcp_option_find_ti(th, ti_pub, ti_tag)) {
			__be32 peer_addr = c->is_client ? c->daddr : c->saddr;
			int ret = tcps_tofu_verify(peer_addr, ti_pub, ti_tag,
						   c->client_isn,
						   c->server_isn,
						   !c->is_client,
						   c->peer_epoch);
			if (ret < 0 && tcps_tofu_enforce) {
				pr_warn("tcps: dropping packet from %pI4 - TOFU verification failed\n",
					&peer_addr);
				c->state = TCPS_DEAD;
				spin_unlock(&c->lock);
				rcu_read_unlock();
				return NF_DROP;
			}
			c->ti_recv = 1;
			c->state = TCPS_AUTHENTICATED;
			pr_info("tcps: session authenticated %pI4:%u <-> %pI4:%u (TOFU+auth_tag)\n",
				&c->saddr, ntohs(c->sport),
				&c->daddr, ntohs(c->dport));
		}
	}

	tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
	payload_off = th->doff * 4;
	payload_len = tcplen - payload_off;
	if (payload_len < 0)
		payload_len = 0;

	if (payload_len > 0 || th->fin) {
		uint8_t tcp_flags = ((uint8_t *)th)[13];
		int embed_ti = (c->state == TCPS_ENCRYPTED && !c->ti_recv &&
				payload_len > 0 &&
				*(__be32 *)((uint8_t *)th + payload_off) ==
					htonl(0x01000000));

		if (!tcp_option_find_mac(th, recv_tag)) {
			pr_warn("tcps: no MAC option, dropping\n");
			spin_unlock(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		pos = tcps_recv_pos(c, ntohl(th->seq));

		if (embed_ti && payload_len >= TCPS_TI_EMBED_SIZE) {
			uint8_t *ti_p = (uint8_t *)th + payload_off;
			tcps_compute_mac_prefix(c->mac_dec_key, pos, tcp_flags,
						ti_p, TCPS_TI_EMBED_SIZE,
						ti_p + TCPS_TI_EMBED_SIZE,
						payload_len - TCPS_TI_EMBED_SIZE,
						calc_tag);
		} else {
			tcps_compute_mac(c->mac_dec_key, pos, tcp_flags,
					 payload_len > 0 ?
						(uint8_t *)th + payload_off : NULL,
					 payload_len, calc_tag);
		}

		if (crypto_memneq(recv_tag, calc_tag, TCPS_MAC_TAG_SIZE)) {
			pr_warn("tcps: MAC verification failed, dropping\n");
			spin_unlock(&c->lock);
			rcu_read_unlock();
			return NF_DROP;
		}

		if (payload_len > 0) {
			int dec_off = (embed_ti &&
				       payload_len >= TCPS_TI_EMBED_SIZE) ?
				      TCPS_TI_EMBED_SIZE : 0;
			payload = (uint8_t *)th + payload_off + dec_off;
			chacha20_xor_stream(c->dec_key, pos, payload,
					    payload_len - dec_off);
		}

		if (embed_ti && payload_len >= TCPS_TI_EMBED_SIZE) {
			uint8_t *ti_p = (uint8_t *)th + payload_off;
			__be32 peer_addr = c->is_client ? c->daddr : c->saddr;
			int app_len = payload_len - TCPS_TI_EMBED_SIZE;

			memcpy(ti_pub, ti_p + 1, TCPS_DH_SIZE);
			memcpy(ti_tag, ti_p + 1 + TCPS_DH_SIZE,
			       TCPS_AUTH_TAG_SIZE);

			{
				int ret = tcps_tofu_verify(peer_addr, ti_pub,
							   ti_tag,
							   c->client_isn,
							   c->server_isn,
							   !c->is_client,
							   c->peer_epoch);
				if (ret < 0 && tcps_tofu_enforce) {
					pr_warn("tcps: embedded TI TOFU failed for %pI4\n",
						&peer_addr);
					c->state = TCPS_DEAD;
					spin_unlock(&c->lock);
					rcu_read_unlock();
					return NF_DROP;
				}
			}
			c->ti_recv = 1;
			c->state = TCPS_AUTHENTICATED;
			pr_info("tcps: session authenticated (embedded TI) %pI4:%u <-> %pI4:%u\n",
				&c->saddr, ntohs(c->sport),
				&c->daddr, ntohs(c->dport));

			if (app_len > 0) {
				memmove((uint8_t *)th + payload_off,
					(uint8_t *)th + payload_off +
					TCPS_TI_EMBED_SIZE,
					app_len);
			}
			skb_trim(skb, skb->len - TCPS_TI_EMBED_SIZE);
			iph = ip_hdr(skb);
			th = tcp_hdr(skb);
			iph->tot_len = htons(ntohs(iph->tot_len) -
					     TCPS_TI_EMBED_SIZE);
			iph->check = 0;
			iph->check = ip_fast_csum((unsigned char *)iph,
						  iph->ihl);
			tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
			th->check = 0;
			th->check = csum_tcpudp_magic(
				iph->saddr, iph->daddr,
				tcplen, IPPROTO_TCP,
				csum_partial(th, tcplen, 0));
			skb->ip_summed = CHECKSUM_NONE;
		} else if (payload_len > 0) {
			th->check = 0;
			th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
						      tcplen, IPPROTO_TCP,
						      csum_partial(th, tcplen, 0));
			skb->ip_summed = CHECKSUM_NONE;
		}
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

static void tcps_keyring_save(void)
{
	pr_info("tcps: identity fingerprint for rotation: %*phN\n",
		8, tcps_static_pub);
}

static void tcps_keyring_check(void)
{
}

static void tcps_compute_send_auth_tag(struct tcps_conn *c,
				       uint8_t auth_tag[TCPS_AUTH_TAG_SIZE])
{
	struct tcps_peer_entry *pe;
	uint32_t ph = jhash_1word(
		(__force u32)(c->is_client ? c->daddr : c->saddr), 0);

	memset(auth_tag, 0, TCPS_AUTH_TAG_SIZE);
	hash_for_each_possible_rcu(tcps_peers_table, pe, hnode, ph) {
		__be32 peer_addr = c->is_client ? c->daddr : c->saddr;
		if (pe->addr == peer_addr) {
			uint8_t shared[TCPS_DH_SIZE];
			if (tcps_dh_shared(tcps_static_priv, pe->pubkey,
					   shared) == 0) {
				tcps_compute_auth_tag(shared, c->client_isn,
						      c->server_isn,
						      c->is_client, auth_tag);
			}
			memzero_explicit(shared, sizeof(shared));
			break;
		}
	}
}

static int __init tcps_init(void)
{
	int err;

	tcps_dh_keygen(tcps_static_priv, tcps_static_pub);
	tcps_epoch = get_random_u32();
	tcps_keyring_check();

	err = nf_register_net_hooks(&init_net, tcps_ops, ARRAY_SIZE(tcps_ops));
	if (err) {
		pr_err("tcps: failed to register hooks\n");
		memzero_explicit(tcps_static_priv, sizeof(tcps_static_priv));
		memzero_explicit(tcps_static_pub, sizeof(tcps_static_pub));
		return err;
	}
	schedule_delayed_work(&tcps_gc_work, TCPS_GC_INTERVAL);
	pr_info("tcps: module loaded, ECDH (X25519) + ChaCha20-Poly1305 + TOFU active\n");
	pr_info("tcps: identity fingerprint: %*phN epoch: %u\n",
		8, tcps_static_pub, tcps_epoch);
	return 0;
}

static void __exit tcps_exit(void)
{
	cancel_delayed_work_sync(&tcps_gc_work);
	nf_unregister_net_hooks(&init_net, tcps_ops, ARRAY_SIZE(tcps_ops));
	tcps_keyring_save();
	tcps_conn_cleanup();
	tcps_tofu_cleanup();
	memzero_explicit(tcps_static_priv, sizeof(tcps_static_priv));
	memzero_explicit(tcps_static_pub, sizeof(tcps_static_pub));
	pr_info("tcps: module unloaded\n");
}

module_init(tcps_init);
module_exit(tcps_exit);
