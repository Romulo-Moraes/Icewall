#ifndef __NET_HOOK_GUARD__
#define __NET_HOOK_GUARD__

#include <linux/netfilter.h>

struct nf_hook_ops generate_inc_net_hook_conf(void);
struct nf_hook_ops generate_out_net_hook_conf(void);
unsigned int inc_net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int out_net_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

#endif