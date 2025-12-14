#include "dfw_flow.h"
#include <rte_jhash.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

uint32_t dfw_flow_key_hash(struct flow_key *key, uint32_t length, uint32_t init_val) {
    return rte_jhash((void *)key, length, init_val);
}

uint32_t dfw_flow_key_hash_from_mbuf(struct rte_mbuf *mbuf) {
    assert(mbuf != NULL);
    struct flow_key key;
    dfw_flow_key_parse(mbuf, &key);
    return dfw_flow_key_hash(&key, sizeof(struct flow_key), 0);
}

void dfw_flow_key_parse(struct rte_mbuf *mbuf, struct flow_key *key) {
    assert(mbuf != NULL && key != NULL);
    struct rte_ether_hdr *eth_hdr = NULL;
    struct rte_ipv4_hdr *ipv4_hdr = NULL;
    struct rte_tcp_hdr *tcp_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    uint16_t eth_type = 0;
    uint8_t ip_proto = 0;

    eth_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);

    if (eth_type == RTE_ETHER_TYPE_IPV4) {
        ipv4_hdr = (struct rte_ipv4_hdr *)(eth_hdr + 1);
        key->ip_src = ipv4_hdr->src_addr;
        key->ip_dst = ipv4_hdr->dst_addr;
        ip_proto = ipv4_hdr->next_proto_id;
        key->proto = ip_proto;

        if (ip_proto == IPPROTO_TCP) {
            tcp_hdr = (struct rte_tcp_hdr *)((unsigned char *)ipv4_hdr + 
                        ((ipv4_hdr->version_ihl & 0x0f) << 2));
            key->port_src = tcp_hdr->src_port;
            key->port_dst = tcp_hdr->dst_port;
        } else if (ip_proto == IPPROTO_UDP) {
            udp_hdr = (struct rte_udp_hdr *)((unsigned char *)ipv4_hdr + 
                        ((ipv4_hdr->version_ihl & 0x0f) << 2));
            key->port_src = udp_hdr->src_port;
            key->port_dst = udp_hdr->dst_port;
        } else {
            key->port_src = 0;
            key->port_dst = 0;
        }
    } else {
        key->ip_src = 0;
        key->ip_dst = 0;
        key->port_src = 0;
        key->port_dst = 0;
        key->proto = 0;
    }
}

