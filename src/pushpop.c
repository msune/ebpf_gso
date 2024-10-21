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
		bpf_printk("[%p] ptr %p on pkt with length: %d out of bounds!\n",\
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

static __always_inline __attribute__((__unused__))
int push_udp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr* ip,
						struct tcphdr *tcp)
{
	int rc;
	struct iphdr old_ip;
	struct udphdr udp, *udp_ptr;
	struct pseudo_header old, new;
	__u32 l3_off  = (__u8*)ip - (__u8*)eth;
	__u16 tot_len;

	//Easier to diff
	old_ip = *ip;

	//L3 changes
	ip->protocol = 17;
	tot_len = bpf_ntohs(ip->tot_len) + HDR_SIZE;
	ip->tot_len = bpf_htons(tot_len);

	//Adjust L3 csum and make room for UDP (so that we only need to reeval
	//ptrs one time).
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

	//Reval ptrs
	eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);
	ip = (struct iphdr*) (eth+1);
	CHECK_SKB_PTR(skb, ip+1);
	udp_ptr = (struct udphdr*) (ip+1);
	CHECK_SKB_PTR(skb, udp_ptr+1);
	tcp = (struct tcphdr*) (udp_ptr+1);
	CHECK_SKB_PTR(skb, tcp+1);

	//Set UDP encap info
	udp.source = tcp->source;
	udp.dest = bpf_htons(TUN_PORT);
	udp.check = 0;
	udp.len = bpf_htons(tot_len - (ip->ihl * 4));

	//Take TCP csum as basis (payload)
	diff = csum_fold(tcp->check);

	//pseudohdr csum_diff
	old.res = 0x0;
	old.proto = 6;
	old.len = bpf_htons(tot_len - HDR_SIZE - (ip->ihl * 4));

	new = old;
	new.proto = 17;
	new.len = bpf_htons(tot_len - (ip->ihl * 4));
	diff = bpf_csum_diff((__be32*)&old, sizeof(old), (__be32*)&new,
							sizeof(new), diff);

	//Adjust old L4 csum (0ed TCP csum, now payload)
	__be16 tcp_csum[2] = {tcp->check, 0};
	diff = bpf_csum_diff(0, 0, (__be32*)&tcp_csum, 4, diff);

	//Add new HDR
	diff = bpf_csum_diff(0, 0, (__be32*)&udp, sizeof(udp), diff);
	udp.check = csum_fold(diff);
	*udp_ptr = udp;

	return TC_ACT_UNSPEC;
}

static __always_inline __attribute__((__unused__))
int pop_udp(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr* ip,
						struct udphdr *udp)
{
	int rc;
	struct iphdr old_ip;
	__u32 l3_off  = (__u8*)ip - (__u8*)eth;
	__u16 tot_len;

	//Easier to diff
	old_ip = *ip;

	//UDP decap
	ip->protocol = 6;
	tot_len = bpf_ntohs(ip->tot_len) - HDR_SIZE;
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
	rc = bpf_skb_adjust_room(skb, -HDR_SIZE, BPF_ADJ_ROOM_NET, 0);
	if (rc < 0) {
		bpf_printk("[%p] Unable to bpf_skb_adjust_room: %d", skb, rc);
		return rc;
	}

	return TC_ACT_UNSPEC;
}

SEC("classifier")
int tcponudp(struct __sk_buff *skb)
{
	struct ethhdr *eth;
	struct iphdr* ip;

	eth = (void *)(unsigned long long)skb->data;
	CHECK_SKB_PTR(skb, eth+1);

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	ip = (struct iphdr*) (eth+1);
	CHECK_SKB_PTR(skb, ip+1);

#ifdef PUSH
	struct tcphdr *tcp;

	if (ip->protocol != IPPROTO_TCP)
		return TC_ACT_UNSPEC;

	tcp = (struct tcphdr*) (ip+1);
	CHECK_SKB_PTR(skb, tcp+1);

	if (tcp->dest != bpf_htons(PORT))
		return TC_ACT_UNSPEC;

	return push_udp(skb, eth, ip, tcp);
#else //PUSH
	struct udphdr *udp;

	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_UNSPEC;

	udp = (struct udphdr*) (ip+1);
	CHECK_SKB_PTR(skb, udp+1);

	if (udp->dest != bpf_htons(TUN_PORT))
		return TC_ACT_UNSPEC;

	return pop_udp(skb, eth, ip, udp);
#endif //PUSH
}

char ____license[] __attribute__((section("license"), used)) = "Dual BSD/GPL";
