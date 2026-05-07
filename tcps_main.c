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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ArtamonovKA (GLM-5.1)");
MODULE_DESCRIPTION("Transparent TCP encryption: X25519 + ChaCha20 + TOFU");

#define TCPS_MAX_SKIP_PORTS 8
static int tcps_skip_ports[TCPS_MAX_SKIP_PORTS] = { 22 };
static int tcps_skip_count = 1;
module_param_array_named(skip_ports, tcps_skip_ports, int, &tcps_skip_count, 0644);
MODULE_PARM_DESC(skip_ports, "Ports to skip (already encrypted, e.g. 22 443)");

static int tcps_should_skip(__be16 port)
{
	int i;
	for (i = 0; i < tcps_skip_count && i < TCPS_MAX_SKIP_PORTS; i++)
		if (ntohs(port) == tcps_skip_ports[i])
			return 1;
	return 0;
}

static int tcps_strict_tofu;
module_param_named(strict_tofu, tcps_strict_tofu, int, 0644);
MODULE_PARM_DESC(strict_tofu, "1=reject key changes (block MITM, breaks reload); 0=accept with warning (default)");

static uint8_t tcps_my_private[CURVE25519_KEY_SIZE];
static uint8_t tcps_my_public[CURVE25519_KEY_SIZE];

static DEFINE_HASHTABLE(tcps_table, TCPS_HASH_BITS);
static DEFINE_SPINLOCK(tcps_lock);

static DEFINE_HASHTABLE(tcps_peers, TCPS_PEER_HASH_BITS);
static DEFINE_SPINLOCK(tcps_peers_lock);

#define TCPS_OPT_KIND	253
#define TCPS_OPT_LEN	4
#define TCPS_OPT_MAGIC	0x5443

#define TCPS_DISC_PORT	54321
#define TCPS_DISC_MAGIC	0x54435053

struct tcps_disc_pkt {
	__be32 magic;
	uint8_t pubkey[CURVE25519_KEY_SIZE];
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

static int tcps_peer_add(__be32 addr, const uint8_t public_key[32])
{
	struct tcps_peer *p, *old;
	uint32_t h;

	old = tcps_peer_lookup(addr);
	if (old) {
		if (memcmp(old->public_key, public_key, 32) == 0)
			return 0;
		if (tcps_strict_tofu) {
			pr_alert("tcps: STRICT TOFU: key change BLOCKED for %pI4\n",
				 &addr);
			return -EPERM;
		}
		pr_warn("tcps: TOFU key change for %pI4 (updating)\n", &addr);
		spin_lock(&tcps_peers_lock);
		memcpy(old->public_key, public_key, 32);
		old->first_seen = jiffies;
		spin_unlock(&tcps_peers_lock);
		return 0;
	}

	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		return -ENOMEM;

	p->addr = addr;
	memcpy(p->public_key, public_key, 32);
	p->first_seen = jiffies;

	h = jhash_1word((__force u32)addr, 0);
	spin_lock(&tcps_peers_lock);
	hash_add_rcu(tcps_peers, &p->hnode, h);
	spin_unlock(&tcps_peers_lock);

	pr_info("tcps: TOFU added peer %pI4\n", &addr);
	return 0;
}

static int tcps_get_dh_secret(__be32 peer_addr, uint8_t shared[32])
{
	struct tcps_peer *p;
	uint8_t peer_pk[32];

	rcu_read_lock();
	p = tcps_peer_lookup(peer_addr);
	if (!p) {
		rcu_read_unlock();
		memset(shared, 0, 32);
		pr_warn("tcps: unknown peer %pI4, using weak keys\n", &peer_addr);
		return -ENOENT;
	}
	memcpy(peer_pk, p->public_key, 32);
	rcu_read_unlock();

	if (tcps_dh_shared(tcps_my_private, peer_pk, shared)) {
		memset(shared, 0, 32);
		return -EINVAL;
	}
	return 0;
}

static void tcps_recalc_csum(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = tcp_hdr(skb);
	int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
	th->check = 0;
	th->check = csum_tcpudp_magic(iph->saddr, iph->daddr,
				      tcplen, IPPROTO_TCP,
				      csum_partial(th, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE;
}

static int tcps_has_probe(const struct tcphdr *th, int tcplen)
{
	int off = sizeof(*th);
	const uint8_t *opt = (const uint8_t *)th;

	while (off + 1 < tcplen) {
		if (opt[off] == 0)
			return 0;
		if (opt[off] == 1) {
			off++;
			continue;
		}
		if (off + opt[off + 1] > tcplen || opt[off + 1] < 2)
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

static uint64_t tcps_send_pos(struct tcps_conn *c, uint32_t seq)
{
	uint32_t base = c->is_client ? c->client_isn + 1 : c->server_isn + 1;
	return (uint64_t)(seq - base);
}

static uint64_t tcps_recv_pos(struct tcps_conn *c, uint32_t seq)
{
	uint32_t base = c->is_client ? c->server_isn + 1 : c->client_isn + 1;
	return (uint64_t)(seq - base);
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
				       __be32 daddr, __be32 dport)
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

static void tcps_conn_free_rcu(struct rcu_head *rh)
{
	struct tcps_conn *c = container_of(rh, struct tcps_conn, rcu);
	memzero_explicit(c->enc_key, sizeof(c->enc_key));
	memzero_explicit(c->dec_key, sizeof(c->dec_key));
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
	uint8_t shared[32];
	__be32 peer_addr;

	peer_addr = c->is_client ? c->daddr : c->saddr;

	if (tcps_get_dh_secret(peer_addr, shared) < 0)
		memset(shared, 0, 32);

	tcps_derive_keys(shared, c->client_isn, c->server_isn,
			 c->is_client, enc_key, dec_key);

	memcpy(c->enc_key, enc_key, TCPS_KEY_SIZE);
	memcpy(c->dec_key, dec_key, TCPS_KEY_SIZE);
	memzero_explicit(enc_key, sizeof(enc_key));
	memzero_explicit(dec_key, sizeof(dec_key));
	memzero_explicit(shared, sizeof(shared));

	c->keys_derived = 1;
	c->state = TCPS_KEYED;
}

static int tcps_is_fragment(struct sk_buff *skb)
{
	if (!skb || skb->len < (int)sizeof(struct iphdr))
		return 1;
	return ip_hdr(skb)->frag_off & htons(IP_OFFSET | IP_MF);
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
				c = tcps_conn_add(iph->saddr, th->source,
						  iph->daddr, th->dest);
				if (c) {
					spin_lock_bh(&c->lock);
					c->state = TCPS_PROBE_SYN;
					c->is_client = 1;
					c->client_isn = ntohl(th->seq);
					c->last_active = jiffies;
					spin_unlock_bh(&c->lock);
				}
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

		if (skb->ip_summed != CHECKSUM_PARTIAL)
			tcps_recalc_csum(skb);
	}

	if (th->fin) {
		c->fin_out = 1;
		if (c->fin_in)
			c->state = TCPS_DEAD;
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
			c = tcps_conn_add(iph->saddr, th->source,
					  iph->daddr, th->dest);
			if (c) {
				spin_lock(&c->lock);
				c->state = TCPS_PROBE_SYNACK;
				c->is_client = 0;
				c->client_isn = ntohl(th->seq);
				c->last_active = jiffies;
				spin_unlock(&c->lock);
			}
		}
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->syn && th->ack) {
		int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;
		int has_probe = tcps_has_probe(th, tcplen);

		c = tcps_conn_lookup(iph->daddr, th->dest, iph->saddr, th->source);
		if (c) {
			spin_lock(&c->lock);
			if (c->state == TCPS_PROBE_SYN && has_probe) {
				c->server_isn = ntohl(th->seq);
				if (c->client_isn && c->server_isn && !c->keys_derived)
					tcps_derive_conn_keys(c);
			} else if (c->state == TCPS_PROBE_SYN && !has_probe) {
				spin_unlock(&c->lock);
				tcps_conn_remove(c);
				rcu_read_unlock();
				return NF_ACCEPT;
			}
			spin_unlock(&c->lock);
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

	spin_lock(&c->lock);
	c->last_active = jiffies;

	if (c->state != TCPS_KEYED) {
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	if (th->rst) {
		c->kill = 1;
		c->state = TCPS_DEAD;
		spin_unlock(&c->lock);
		rcu_read_unlock();
		return NF_ACCEPT;
	}

	payload_off = iph->ihl * 4 + th->doff * 4;
	payload_len = ntohs(iph->tot_len) - payload_off;
	if (payload_len < 0)
		payload_len = 0;

	if (payload_len > 0 && c->keys_derived) {
		pos = tcps_recv_pos(c, ntohl(th->seq));

		if (payload_off + payload_len > skb->len) {
			spin_unlock(&c->lock);
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
			c->state = TCPS_DEAD;
	}

	spin_unlock(&c->lock);
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
	if (ret != sizeof(pkt))
		return ret;

	if (pkt.magic != htonl(TCPS_DISC_MAGIC))
		return -EINVAL;

	if (memcmp(pkt.pubkey, tcps_my_public, CURVE25519_KEY_SIZE) == 0)
		return 0;

	tcps_peer_add(addr.sin_addr.s_addr, pkt.pubkey);
	return 0;
}

static void tcps_disc_send(struct socket *sock)
{
	struct tcps_disc_pkt pkt;
	struct sockaddr_in addr;
	struct msghdr msg = {};
	struct kvec iov;

	memset(&pkt, 0, sizeof(pkt));
	pkt.magic = htonl(TCPS_DISC_MAGIC);
	memcpy(pkt.pubkey, tcps_my_public, CURVE25519_KEY_SIZE);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCPS_DISC_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

	iov.iov_base = &pkt;
	iov.iov_len = sizeof(pkt);
	msg.msg_name = &addr;
	msg.msg_namelen = sizeof(addr);

	kernel_sendmsg(sock, &msg, &iov, 1, sizeof(pkt));
}

static int tcps_disc_thread(void *data)
{
	struct socket *sock;
	struct sockaddr_in addr;
	int ret, val;

	ret = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (ret)
		return ret;

	val = 1;
	do_sock_setsockopt(sock, false, SOL_SOCKET, SO_BROADCAST,
			   KERNEL_SOCKPTR(&val), sizeof(val));
	sock->sk->sk_rcvtimeo = HZ;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCPS_DISC_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));

	tcps_disc_sock = sock;

	while (!kthread_should_stop()) {
		tcps_disc_send(sock);

		while (!kthread_should_stop())
			if (tcps_disc_recv(sock) < 0)
				break;

		schedule_timeout_interruptible(HZ * 3);
	}

	sock_release(sock);
	tcps_disc_sock = NULL;
	return 0;
}

static ssize_t tcps_peers_proc_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char kbuf[128];
	uint8_t pubkey[32];
	__be32 addr;
	int i;
	char *p;

	if (count > sizeof(kbuf) - 1)
		return -EINVAL;
	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;
	kbuf[count] = 0;

	p = strchr(kbuf, '=');
	if (!p)
		return -EINVAL;
	*p = 0;
	if (!in4_pton(kbuf, -1, (u8 *)&addr, -1, NULL))
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
		seq_printf(m, "%pI4=", &p->addr);
		for (j = 0; j < 32; j++)
			seq_printf(m, "%02x", p->public_key[j]);
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
	tcps_gen_keypair(tcps_my_private, tcps_my_public);

	pr_info("tcps: X25519 identity generated, pubkey=");
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

	pr_info("tcps: module loaded, X25519 + ChaCha20 + TOFU active\n");
	return 0;
}

static void __exit tcps_exit(void)
{
	struct tcps_conn *c;
	struct tcps_peer *p;
	int i;

	cancel_delayed_work_sync(&tcps_cleanup);
	nf_unregister_net_hooks(&init_net, tcps_nf_ops, ARRAY_SIZE(tcps_nf_ops));

	if (tcps_disc_task)
		kthread_stop(tcps_disc_task);

	remove_proc_entry("tcps_peers", NULL);

	rcu_read_lock();
	hash_for_each_rcu(tcps_table, i, c, hnode)
		tcps_conn_remove(c);
	hash_for_each_rcu(tcps_peers, i, p, hnode) {
		spin_lock(&tcps_peers_lock);
		hash_del_rcu(&p->hnode);
		spin_unlock(&tcps_peers_lock);
		call_rcu(&p->rcu, (void (*)(struct rcu_head *))kfree);
	}
	rcu_read_unlock();
	synchronize_rcu();

	memzero_explicit(tcps_my_private, sizeof(tcps_my_private));
	pr_info("tcps: module unloaded\n");
}

module_init(tcps_init);
module_exit(tcps_exit);
