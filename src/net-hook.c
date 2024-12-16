#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/byteorder/little_endian.h>
#include "../includes/net-hook.h"
#include "../includes/sentinel.h"

struct nf_hook_ops generate_net_hook_conf(void) {
    struct nf_hook_ops hook_ops = {
        .hook = net_hook,
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_PRE_ROUTING,
        .priority = 0
    };

    return hook_ops;
}

unsigned int net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    action act;
    u16 dport;

    if (skb == NULL) {
        return NF_ACCEPT;
    }

    struct iphdr *iph = ip_hdr(skb);

    if (!iph) {
        return NF_ACCEPT;
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);

        dport = ntohs(tcph->dest);
    } else if (iph->protocol == IPPROTO_UDP){
        struct udphdr *udph = (struct udphdr*)((__u32*)iph + iph->ihl);
        dport = ntohs(udph->dest);
    }

    test_packet((struct packet) {
        .addr = ntohl(iph->saddr),
        .hport = dport,
        .proto = iph->protocol
    }, DIRECTION_IN, &act);

    return (act == POLICY_DROP ? NF_DROP : NF_ACCEPT);
}

EXPORT_SYMBOL(generate_net_hook_conf);
EXPORT_SYMBOL(net_hook);
