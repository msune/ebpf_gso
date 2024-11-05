#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define PORT 8080
#define TUN_PORT 80
#define HDR_SIZE 8 //20
#define CHECK_SKB_PTR_VAL( SKB, PTR, VAL ) \
	if (  (void*)(PTR) > ((void*)(unsigned long long) SKB -> data_end )) {	\
		bpf_printk("[0x%llx] ptr %p on pkt with length: %d out of bounds!\n",\
							SKB, PTR, SKB ->len);	\
		return VAL;							\
	} do{}while(0)
#define CHECK_SKB_PTR( SKB, PTR ) CHECK_SKB_PTR_VAL( SKB, PTR, TC_ACT_UNSPEC)

struct __attribute__((packed)) pseudo_header {
	__u8 res;
	__u8 proto;
	__be16 len;
};

//Taken from Cilium
static __always_inline __attribute__((__unused__))
__be16 csum_fold(__s64 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__be16)~csum;
}

SEC("classifier")
int tcponudp(struct __sk_buff *skb)
{
	int rc;
	struct ethhdr *eth;
	struct iphdr* ip;
	struct tcphdr *tcp;

	eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	ip = (struct iphdr*) (eth+1);
	CHECK_SKB_PTR(skb, ip+1);

	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, tcp+1);

	if (tcp->dest != bpf_htons(PORT))
		return TC_ACT_UNSPEC;

#if 10
	//Disable offlods (workaround)
	rc = bpf_skb_change_tail(skb, skb->len, 0);
	(void)rc;
	if (rc < 0) {
		bpf_printk("[%p] Unable to bpf_skb_change_tail_1: %d", skb, rc);
		return rc;
	}
#else
	(void)rc;
#endif
	return TC_ACT_UNSPEC;
}

char ____license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
