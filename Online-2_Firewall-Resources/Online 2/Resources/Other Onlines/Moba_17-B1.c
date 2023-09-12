# 17 - B1



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/inet.h>


static struct nf_hook_ops hook1, hook2; 
static char internal_ip_str[3][16] = {
    "192.168.60.5", 
    "192.168.60.6", 
    "192.168.60.7"
};
static char external_ip_str[2][16] = {
    "10.9.0.5", 
    "10.9.0.1"
};

static char count[2][2] = {{0, 0}, {0, 0}};

unsigned int template_(void *priv, struct sk_buff *skb,
                       const struct nf_hook_state *state)
{
    // IP Header: dst addr, src addr, protocol, ttl
    struct iphdr *iph;
    struct tcphdr *tcph;

    u32 ip_internal[3], ip_external[2];

    u16 i, j;
    for (i=0; i<3; i++)
        in4_pton(internal_ip_str[i], -1, (u8 *)&ip_internal[i], '\0', NULL);

    for (i=0; i<3; i++)
        in4_pton(external_ip_str[i], -1, (u8 *)&ip_external[i], '\0', NULL);

    if (!skb) return NF_ACCEPT;

    iph = ip_hdr(skb);

    for (i=0; i<3; i++) {
        for (j=0; j<2; j++) {
            if ((iph->saddr == ip_internal[i] && iph->daddr == ip_external[j]) || 
                (iph->saddr == ip_external[j] && iph->daddr == ip_internal[i])) {
                if (iph->protocol == IPPROTO_TCP) {
                    tcph = tcp_hdr(skb);
                    if (ntohs(tcph->dest) != 23)
                        return NF_DROP;
                }else return NF_DROP;
            }
        }
    }

    for (j=0; j<2; j++) {
        if (iph->saddr == ip_external[j]) {
            if (tcp_hdr(skb)->syn) {
                if(count[j][0] > 3)
                    return NF_DROP;
                count[j][0]++;
            }
        }
    }

    return NF_ACCEPT;
}

unsigned int printInfo(void *priv, struct sk_buff *skb,
                 const struct nf_hook_state *state)
{
   struct iphdr *iph;
   char *hook;
   char *protocol;

   switch (state->hook){
     case NF_INET_LOCAL_IN:     hook = "LOCAL_IN";     break; 
     case NF_INET_LOCAL_OUT:    hook = "LOCAL_OUT";    break; 
     case NF_INET_PRE_ROUTING:  hook = "PRE_ROUTING";  break; 
     case NF_INET_POST_ROUTING: hook = "POST_ROUTING"; break; 
     case NF_INET_FORWARD:      hook = "FORWARD";      break; 
     default:                   hook = "IMPOSSIBLE";   break;
   }
   printk(KERN_INFO "*** %s\n", hook); // Print out the hook info

   iph = ip_hdr(skb);
   switch (iph->protocol){
     case IPPROTO_UDP:  protocol = "UDP";   break;
     case IPPROTO_TCP:  protocol = "TCP";   break;
     case IPPROTO_ICMP: protocol = "ICMP";  break;
     default:           protocol = "OTHER"; break;

   }
   // Print out the IP addresses and protocol
   printk(KERN_INFO "    %pI4  --> %pI4 (%s)\n", 
                    &(iph->saddr), &(iph->daddr), protocol);

   return NF_ACCEPT;
}


int registerFilter(void) {
   printk(KERN_INFO "Registering filters.\n");

   hook1.hook = printInfo;
   hook1.hooknum = NF_INET_LOCAL_OUT;
   hook1.pf = PF_INET;
   hook1.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook1);

   hook2.hook = template_;
   hook2.hooknum = NF_INET_POST_ROUTING;
   hook2.pf = PF_INET;
   hook2.priority = NF_IP_PRI_FIRST;
   nf_register_net_hook(&init_net, &hook2);

   return 0;
}

void removeFilter(void) {
   printk(KERN_INFO "The filters are being removed.\n");
   nf_unregister_net_hook(&init_net, &hook1);
   nf_unregister_net_hook(&init_net, &hook2);
}

module_init(registerFilter);
module_exit(removeFilter);

MODULE_LICENSE("GPL");