#include <linux/module.h>
#include <linux/kernel.h>
#include "./../includes/net-hook.h"

static struct nf_hook_ops hook_ops;

static int __init entry_procedure(void) {
    hook_ops = generate_net_hook_conf();

    nf_register_net_hook(&init_net, &hook_ops);

    pr_info("Firewall UP and running!\n");

    return 0;
}

static void __exit exit_procedure(void) {
    nf_unregister_net_hook(&init_net, &hook_ops);

    pr_info("Firewall is down!\n");
}

module_init(entry_procedure);
module_exit(exit_procedure);

MODULE_LICENSE("GPL");
