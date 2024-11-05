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
#define HDR_SIZE 20
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
int udp_on_tcp(struct __sk_buff *skb)
{
	int rc;
	struct ethhdr *eth;
	struct iphdr *ip, old_ip;
	struct tcphdr *tcp;
	__u16 tot_len;
	__u16 l3_off;

	eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	ip = (struct iphdr*) (eth+1);
	CHECK_SKB_PTR(skb, ip+1);


	//Easier to diff
	l3_off  = (__u8*)ip - (__u8*)eth;
	old_ip = *ip;

#ifdef PUSH
	struct udphdr *udp;
	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_UNSPEC;

	udp = (struct udphdr *) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, udp+1);

	if (udp->dest != bpf_htons(PORT))
		return TC_ACT_UNSPEC;

	//TCP encap
	ip->protocol = 6;
	tot_len = bpf_ntohs(ip->tot_len) + HDR_SIZE;
	ip->tot_len = bpf_htons(tot_len);

	//total_len
	__s64 diff = bpf_csum_diff((__be32*)&old_ip, 4, (__be32*)ip, 4, 0);
	diff = bpf_csum_diff((__be32*)&old_ip.ttl, 4, (__be32*)&ip->ttl, 4, diff);

	//Adjust IP checksum and make room for the new L4 hdr
	rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
							0,
							diff, 0);
	if (rc < 0) {
		bpf_printk("[%p] Unable to l3_csum_replace: %d", skb, rc);
		return rc;
	}
	rc = bpf_skb_adjust_room(skb, HDR_SIZE, BPF_ADJ_ROOM_NET, 0);
	if (rc < 0) {
		bpf_printk("[%p] Unable to bpf_skb_adjust_room: %d", skb, rc);
		return rc;
	}

	//Add TCP HDR
	eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);
	ip = (struct iphdr*) (eth+1);
	CHECK_SKB_PTR(skb, ip+1);
	tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, tcp+1);
	udp = (struct udphdr *) ((__u8*)tcp + HDR_SIZE);
	CHECK_SKB_PTR(skb, udp+1);

	diff = csum_fold(udp->check);
	__be16 udp_csum[2] = {0, udp->check};
	diff = bpf_csum_diff(0, 0, (__be32*)&udp_csum, 4, diff);

	tcp->dest = bpf_htons(TUN_PORT);
	tcp->source = bpf_htons(540);
	tcp->seq = bpf_htonl(0xCAFEBABE);
	tcp->ack_seq = bpf_htonl(0xBABECAFE);
	*((&tcp->ack_seq)+1) = tcp->urg_ptr = tcp->check = 0x0;
	tcp->syn = 0x1;
	tcp->window = bpf_htons(1024);
	tcp->doff = sizeof(*tcp)/4;
	tcp->check = 0x0;
	diff = bpf_csum_diff(0, 0, (__be32*)tcp, sizeof(*tcp), diff);

	//Set checksum
	tcp->check = csum_fold(diff);
#else
	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	tcp = (struct tcphdr *) ((__u8*)ip + (ip->ihl * 4));
	CHECK_SKB_PTR(skb, tcp+1);

	if (tcp->dest != bpf_htons(TUN_PORT))
		return TC_ACT_UNSPEC;

	//TCP decap
	ip->protocol = 17;
	tot_len = bpf_ntohs(ip->tot_len) - HDR_SIZE;
	ip->tot_len = bpf_htons(tot_len);

	//total_len
	__s64 diff = bpf_csum_diff((__be32*)&old_ip, 4, (__be32*)ip, 4, 0);
	diff = bpf_csum_diff((__be32*)&old_ip.ttl, 4, (__be32*)&ip->ttl, 4, diff);

	//Adjust IP checksum and make room for the new L4 hdr
	rc = bpf_l3_csum_replace(skb, l3_off + offsetof(struct iphdr, check),
							0,
							diff, 0);

	rc = bpf_skb_adjust_room(skb, -HDR_SIZE, BPF_ADJ_ROOM_NET, 0);
	if (rc < 0) {
		bpf_printk("[%p] Unable to bpf_skb_adjust_room: %d", skb, rc);
		return rc;
	}
#endif //PUSH

	//Packet has been mangled, mark it as such
	//bpf_set_hash_invalid(skb);

	return TC_ACT_UNSPEC;
}

char ____license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
