#include "dfw_route.h"
#include "dfw_arp.h"
#include "dfw.h"
#include <assert.h>
int dfw_route_init(void) {
    int ret = -1;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    struct rte_lpm_config lpm_cfg = {
        .max_rules = 1024,
        .number_tbl8s = 256,
        .flags = 0
    };

    dfw_ctx->dfw_route_conf.lpm4 = 
        rte_lpm_create("lpm4", 
        rte_socket_id(), 
        &lpm_cfg);
    if(!dfw_ctx->dfw_route_conf.lpm4) {
        dfw_log_write(LOG_ERROR, "dfw_route_init() rte_lpm_create() error.");
        goto __finish;
    }
    for(int i = 0; i < dfw_ctx->dfw_route_conf.route_entry_count; ++i) {
        dfwRouteEntry *entry = &dfw_ctx->dfw_route_conf.route_entries[i];
        uint32_t depth = __builtin_popcount(entry->netmask);
        if(rte_lpm_add(dfw_ctx->dfw_route_conf.lpm4, entry->destination, depth, i) != 0) {
            dfw_log_write(LOG_ERROR, "dfw_route_init() rte_lpm_add() error.");
            goto __finish;
        }
    }
    ret = 0;
__finish:
    if(ret < 0) {
        dfw_route_destroy();
    }
    return ret;
}

int dfw_route_lookup(uint32_t ip) {
    uint32_t next_hop_index = 0;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    if(rte_lpm_lookup(dfw_ctx->dfw_route_conf.lpm4, ip, &next_hop_index) != 0) {
        dfw_log_write(LOG_WARNING, "dfw_route_lookup() rte_lpm_lookup() no route for ip: %s.", inet_ntoa(*(struct in_addr *)&ip));
        return -1;
    }
    return next_hop_index;
}

void dfw_route_destroy(void) {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    if (dfw_ctx->dfw_route_conf.lpm4) {
        rte_lpm_delete_all(dfw_ctx->dfw_route_conf.lpm4);
        rte_lpm_free(dfw_ctx->dfw_route_conf.lpm4);
        dfw_ctx->dfw_route_conf.lpm4 = NULL;
    }
}

int dfw_route_get_out_portid_and_mac_by_ethname(const char *ethname, uint16_t *out_portid, struct rte_ether_addr *mac_addr) {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    assert(ethname);
    for(int i = 0; i < dfw_ctx->dfw_eth_port_conf.eth_port_entry_count; ++i) {
        dfwEthPortEntry *entry = &dfw_ctx->dfw_eth_port_conf.eth_port_entry[i];
        if(strncmp(entry->eth_name, ethname, RTE_ETH_NAME_MAX_LEN) == 0) {
            *out_portid = entry->port_id;
            if(mac_addr) {
                rte_memcpy(mac_addr->addr_bytes, entry->eth_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
            }
            return 0;
        }
    }
    return -1;
}

dfwPkgProcessResult dfw_route_process(struct rte_ipv4_hdr *ipv4_hdr, 
                                      uint16_t *out_portid, 
                                      struct rte_ether_addr *src_mac, 
                                      struct rte_ether_addr *dst_mac,
                                      struct rte_mbuf *mbuf) {
   
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    int next_hop_index = dfw_route_lookup(ipv4_hdr->dst_addr);
    if(next_hop_index < 0) {
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    if (next_hop_index >= dfw_ctx->dfw_route_conf.route_entry_count) {
        dfw_log_write(LOG_ERROR, "route idx %d out of range", next_hop_index);
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    dfwRouteEntry *route_entry = 
        &dfw_ctx->dfw_route_conf.route_entries[next_hop_index];
    assert(route_entry);
    
    /* 设置输出端口和MAC地址 */
    if(dfw_route_get_out_portid_and_mac_by_ethname(route_entry->out_port, out_portid, src_mac) < 0) {
        dfw_log_write(LOG_ERROR, "dfw_route_process() dfw_route_get_out_portid_by_ethname() error: can not get portid for ethname[%s].",
                       route_entry->out_port);
        return DFW_PKG_PROCESS_RESULT_DROP;
    }

    uint32_t next_hop_ip = 
        route_entry->gateway == 0 ? ipv4_hdr->dst_addr : route_entry->gateway;
   
    dfwArpEntry *arp_entry = dfw_arp_table_lookup(next_hop_ip);
    if(!arp_entry) {
        dfw_send_arp_entry_create_msg(next_hop_ip, *out_portid, src_mac, mbuf);
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    rte_spinlock_lock(&arp_entry->lock);
    if (arp_entry->state == ARP_RESOLVING) {
        dfw_append_mbuf_to_pending(mbuf, arp_entry);
        rte_spinlock_unlock(&arp_entry->lock);
        return DFW_PKG_PROCESS_RESULT_DROP;
    } else if(arp_entry->state == ARP_RESOLVED) {
        /* 更新 mac 地址 */
        rte_memcpy(dst_mac->addr_bytes, arp_entry->dst_mac.addr_bytes, RTE_ETHER_ADDR_LEN);   
    } else if(arp_entry->state == ARP_FREE ||
              arp_entry->state == ARP_FAILED) {
        rte_spinlock_unlock(&arp_entry->lock);
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    rte_spinlock_unlock(&arp_entry->lock);
    /* ttl - 1 */
    ipv4_hdr->time_to_live--;
    return DFW_PKG_PROCESS_RESULT_FORWARD;
}