#include <linux/module.h>
#include <linux/kernel.h>
#include "./../includes/net-hook.h"
#include "./../includes/sentinel.h"
#include "./../includes/chrdev.h"

static struct nf_hook_ops inc_hook_ops;
static struct nf_hook_ops out_hook_ops;

static int __init entry_procedure(void) {
    inc_hook_ops = generate_inc_net_hook_conf();
    out_hook_ops = generate_out_net_hook_conf();
    long chrdev_stt;

    nf_register_net_hook(&init_net, &inc_hook_ops);
    nf_register_net_hook(&init_net, &out_hook_ops);

    init_sentinel();
    
    if ((chrdev_stt = create_rules_chrdev() < 0)) {
        pr_err("Failed to create rules char device. Unable to continue!");
        nf_unregister_net_hook(&init_net, &inc_hook_ops);
        nf_unregister_net_hook(&init_net, &out_hook_ops);

        return -chrdev_stt;
    }

    pr_info("The icewall is up and running!\n");

    return 0;
}

static void __exit exit_procedure(void) {
    nf_unregister_net_hook(&init_net, &inc_hook_ops);
    nf_unregister_net_hook(&init_net, &out_hook_ops);
    destroy_rules_chrdev();

    pr_info("The icewall is down!\n");
}

module_init(entry_procedure);
module_exit(exit_procedure);

MODULE_LICENSE("GPL");
