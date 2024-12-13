#include <linux/ip.h>
#include "../includes/net-hook.h"

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
    if (skb == NULL) {
        return NF_ACCEPT;
    }

    struct iphdr *hdr = ip_hdr(skb);

    if (!hdr) {
        return NF_ACCEPT;
    }

    pr_info("IPv4 Address: %pI4\n", &hdr->saddr);

    return NF_ACCEPT;
}

EXPORT_SYMBOL(generate_net_hook_conf);
EXPORT_SYMBOL(net_hook);

MODULE_LICENSE("GPL");