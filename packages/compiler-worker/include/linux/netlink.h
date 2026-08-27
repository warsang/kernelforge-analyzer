#pragma once
struct sock;
struct net { int dummy; };
extern struct net init_net;
struct netlink_kernel_cfg {
    unsigned int groups;
    unsigned int flags;
    void (*input)(void *skb);
    void *cb_mutex;
};
struct sock *netlink_kernel_create(struct net *net, int unit, struct netlink_kernel_cfg *cfg);
void netlink_kernel_release(struct sock *sk);
struct sk_buff { void *data; unsigned int len; };
