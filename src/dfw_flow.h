#ifndef __DFW_FLOW_H__
#define __DFW_FLOW_H__
#include <rte_byteorder.h>
#include <rte_mbuf.h>

struct flow_key {
	uint32_t ip_src;
	uint32_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;
	uint8_t proto;
} __rte_packed;


uint32_t dfw_flow_key_hash(struct flow_key *key, uint32_t length, uint32_t init_val);
uint32_t dfw_flow_key_hash_from_mbuf(struct rte_mbuf *mbuf);
void dfw_flow_key_parse(struct rte_mbuf *mbuf, struct flow_key *key);

#endif /* __DFW_FLOW_H__ */