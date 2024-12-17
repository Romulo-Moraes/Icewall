#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/little_endian.h>
#include "../includes/net-hook.h"
#include "../includes/sentinel.h"

static u16 extract_port(struct iphdr *iph);

struct nf_hook_ops generate_inc_net_hook_conf(void) {
    struct nf_hook_ops hook_ops = {
        .hook = inc_net_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = 0
    };

    return hook_ops;
}

struct nf_hook_ops generate_out_net_hook_conf(void) {
    struct nf_hook_ops hook_ops = {
        .hook = out_net_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_POST_ROUTING,
        .priority = 0
    };

    return hook_ops;
}

unsigned int inc_net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    action act;
    u16 dport;

    if (skb == NULL) {
        return NF_ACCEPT;
    }

    struct iphdr *iph = ip_hdr(skb);

    if (!iph) {
        return NF_ACCEPT;
    }

    dport = extract_port(iph);

    test_packet((struct packet) {
        .addr = ntohl(iph->saddr),
        .hport = dport,
        .proto = iph->protocol
    }, DIRECTION_IN, &act);

    return (act == POLICY_DROP ? NF_DROP : NF_ACCEPT);
}

unsigned int out_net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    action act;
    u16 dport;

    if (skb == NULL) {
        return NF_ACCEPT;
    }

    struct iphdr *iph = ip_hdr(skb);

    if (!iph) {
        return NF_ACCEPT;
    }

    dport = extract_port(iph);

    test_packet((struct packet) {
        .addr = ntohl(iph->daddr),
        .hport = dport,
        .proto = iph->protocol
    }, DIRECTION_OUT, &act);

    return (act == POLICY_DROP ? NF_DROP : NF_ACCEPT);
}

static u16 extract_port(struct iphdr *iph) {
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);
        return ntohs(tcph->dest);
    } else {
        struct udphdr *udph = (struct udphdr*)((__u32*)iph + iph->ihl);
        return ntohs(udph->dest);
    }
}

EXPORT_SYMBOL(generate_inc_net_hook_conf);
EXPORT_SYMBOL(generate_out_net_hook_conf);
EXPORT_SYMBOL(inc_net_hook);
