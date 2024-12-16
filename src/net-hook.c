#include <linux/ip.h>
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

    if (skb == NULL) {
        return NF_ACCEPT;
    }

    struct iphdr *hdr = ip_hdr(skb);

    if (!hdr) {
        return NF_ACCEPT;
    }

    test_packet((struct packet) {
        .addr = ntohl(hdr->saddr),
        .hport = 8080,
        .proto = hdr->protocol
    }, DIRECTION_IN, &act);

    return (act == POLICY_DROP ? NF_DROP : NF_ACCEPT);
}

EXPORT_SYMBOL(generate_net_hook_conf);
EXPORT_SYMBOL(net_hook);
