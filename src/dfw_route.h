#ifndef __DFW_ROUTE_H__
#define __DFW_ROUTE_H__

#include "dfw.h"
int dfw_route_init(void);

int dfw_route_lookup(uint32_t ip);

void dfw_route_destroy(void);

int dfw_route_get_out_portid_and_mac_by_ethname(const char *ethname, uint16_t *out_portid, struct rte_ether_addr *mac_addr);

dfwPkgProcessResult dfw_route_process(struct rte_ipv4_hdr *ipv4_hdr, 
                                      uint16_t *out_portid, 
                                      struct rte_ether_addr *src_mac, 
                                      struct rte_ether_addr *dst_mac,
                                      struct rte_mbuf *mbuf);
#endif /* __DFW_ROUTE_H__ */