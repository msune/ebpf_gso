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
int fun_unfun_tcp(struct __sk_buff *skb)
{
	int rc;
	struct ethhdr *eth;
	struct iphdr* ip;
	struct tcphdr *tcp;
	__s64 l3_diff, l4_diff;
	__u16 l3_off, l4_off;
	__u8 flow_id = 0x1; //Param
	__be32 l3_tmp;
	__be32 l4_tmp;

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

#ifdef PUSH
	if (tcp->dest != bpf_htons(PORT))
		return TC_ACT_UNSPEC;
#else
	if (tcp->dest != bpf_htons(TUN_PORT))
		return TC_ACT_UNSPEC;
#endif //PUSH

	l3_tmp = *(__be32*)&ip->id;
	l4_tmp = *(__be32*)tcp;

#ifdef PUSH
	//Used reserved flags to encode the flow id
	//This seems to be compatible with TSO/GSO
	tcp->res1 = flow_id;

	//Set tunneling port
	tcp->dest = bpf_htons(TUN_PORT);
#else //PUSH
	if (!tcp->res1)
		return TC_ACT_UNSPEC;

	__u8 pkt_flow_id = tcp->res1;
	if (pkt_flow_id != flow_id) {
		bpf_printk("[0x%llx] Unknown flow_id: %u, id: 0x%x", skb, pkt_flow_id, bpf_ntohs(ip->id));
		return TC_ACT_SHOT;
	}

	//Undo pkt modifications
	//ip->frag_off &= bpf_htons(~0x8000);
	tcp->dest = bpf_htons(PORT);
#endif //PUSH

	//Adjust L3 csum (flags + id)
	l3_diff = bpf_csum_diff(&l3_tmp, 4, (__be32*)&ip->id, 4, 0);
	l3_off = (__u8*)ip - (__u8*)eth + offsetof(struct iphdr, check);
	l4_diff = bpf_csum_diff(&l4_tmp, 4, (__be32*)tcp, 4, 0);
	l4_off = (__u8*)tcp - (__u8*)eth + offsetof(struct tcphdr, check);

	rc = bpf_l3_csum_replace(skb, l3_off, 0, l3_diff, 0);
	if (rc < 0) {
		bpf_printk("[0x%llx] Unable to bpf_l3_csum_replace: %d", skb, rc);
		return TC_ACT_SHOT;
	}
	//Adjust L4 csum (dstport)
	rc = bpf_l4_csum_replace(skb, l4_off, 0, l4_diff, 0);
	if (rc < 0) {
		bpf_printk("[0x%llx] Unable to bpf_l4_csum_replace: %d", skb, rc);
		return TC_ACT_SHOT;
	}

	//Packet has been mangled, mark it as such
	//bpf_set_hash_invalid(skb);

	return TC_ACT_UNSPEC;
}

char ____license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
