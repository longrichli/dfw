#include "dfw.h"
#include "dfw_nat.h"
#include "dfw_tools.h"
#include <stdint.h>
#include <rte_byteorder.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_hash.h>
#include <rte_jhash.h>

int dfw_nat_send_create_nat_entry_msg(dfwSnatKey *key, uint16_t out_port) {
    assert(key);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfwCommMsg *msg = rte_malloc("dfwCommMsg", sizeof(dfwCommMsg), 0);
    if(!msg) {
        dfw_log_write(LOG_ERROR, "dfw_nat_send_create_nat_entry_msg() rte_malloc() error: can not" 
                                    "create dfwCommMsg.");
        return -1;
    }
    dfwNatCreateMsg *nat_create_msg = rte_malloc("dfwNatCreateMsg", sizeof(dfwNatCreateMsg), 0);
    if(!nat_create_msg) {
        rte_free(msg);
        return -1;
    }
    nat_create_msg->lan_ip = key->lan_ip;
    nat_create_msg->lan_port = key->lan_port;
    nat_create_msg->protocol = key->protocol;
    nat_create_msg->remote_ip = key->remote_ip;
    nat_create_msg->remote_port = key->remote_port;
    nat_create_msg->out_port = out_port;
    msg->msg_type = DFW_MSG_CREATE_NAT_ENTRY;
    msg->msg_content = nat_create_msg;
    if(rte_ring_mp_enqueue(dfw_ctx->dfw_ring_conf.msg_from_proc_lcore, (void *)msg) != 0) {
        rte_free(msg);
        rte_free(nat_create_msg);
        return -1;
    }
    return 0;
}

int dfw_nat_create_msg_process(dfwNatCreateMsg *msg) {
    assert(msg);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfwSnatKey snat_key = {
        .lan_ip = msg->lan_ip,
        .lan_port = msg->lan_port,
        .protocol = msg->protocol,
        .remote_ip = msg->remote_ip,
        .remote_port = msg->remote_port
    };
    dfwDnatKey dnat_key = {
        .protocol = msg->protocol,
        .remote_ip = msg->remote_ip,
        .remote_port = msg->remote_port,
        .wan_ip = dfw_ctx->dfw_eth_port_conf.eth_port_mapping[msg->out_port]->ip,
        .wan_port = (rte_jhash(&snat_key, sizeof(dfwSnatKey), 
                    dfw_ctx->dfw_nat_conf.nat_port_alloc_hash_seed) 
                    % (65535 - 1024 + 1)) + 1024,
    };
    
    if(rte_hash_lookup(dfw_ctx->dfw_nat_conf.snat_table, (void *)&snat_key) < 0 &&
       rte_hash_lookup(dfw_ctx->dfw_nat_conf.dnat_table, (void *)&dnat_key) < 0 ) {
        dfwNatEntry *nat_entry = rte_malloc("dfwNatEntry", sizeof(dfwNatEntry), 0);
        if(!nat_entry) {
            dfw_log_write(LOG_ERROR, "dfw_nat_create_msg_process() rte_malloc() error: can not create dfwNatEntry.");
            return -1;
        }
        nat_entry->lan_ip = msg->lan_ip;
        nat_entry->lan_port = msg->lan_port;
        nat_entry->protocol = msg->protocol;
        nat_entry->wan_ip = dnat_key.wan_ip;
        nat_entry->wan_port = dnat_key.wan_port;
        rte_atomic64_set(&nat_entry->last_seen_tsc, (int64_t)rte_get_tsc_cycles());
        nat_entry->state = DFW_NAT_ENTRY_ALIVE;
        rte_hash_add_key_data(dfw_ctx->dfw_nat_conf.snat_table, 
                              (void *)&snat_key, (void *)nat_entry);
        rte_hash_add_key_data(dfw_ctx->dfw_nat_conf.dnat_table, 
                              (void *)&dnat_key, (void *)nat_entry);
    }
    return 0;
}

dfwPkgProcessResult dfw_nat_snat_process(struct rte_ipv4_hdr *ipv4_hdr, uint16_t out_port) {
    assert(ipv4_hdr);
    struct rte_tcp_hdr *tcp_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp_hdr = (struct rte_tcp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
    } else if(ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        udp_hdr = (struct rte_udp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
    } else {
        /* only support tcp and udp */
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    
    /* SNAT */
    dfwSnatKey key;
    key.protocol = ipv4_hdr->next_proto_id;
    key.remote_ip = ipv4_hdr->dst_addr;
    key.lan_ip = ipv4_hdr->src_addr;
    
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        key.lan_port = tcp_hdr->src_port;
        key.remote_port = tcp_hdr->dst_port;
    } else if(ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        key.lan_port = udp_hdr->src_port;
        key.remote_port = udp_hdr->dst_port;
    }

    dfwNatEntry *nat_entry = NULL;
    if(rte_hash_lookup_data(dfw_ctx->dfw_nat_conf.snat_table, 
                            (void *)&key, (void **)&nat_entry) < 0) {
        dfw_nat_send_create_nat_entry_msg(&key, out_port);
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    assert(nat_entry);
    rte_atomic64_set(&nat_entry->last_seen_tsc, (int64_t)rte_get_tsc_cycles());
    ipv4_hdr->src_addr = nat_entry->wan_ip;
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp_hdr->src_port = nat_entry->wan_port;
        tcp_hdr->cksum = 0;
    } else if(ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        udp_hdr->src_port = nat_entry->wan_port;
        udp_hdr->dgram_cksum = 0;
    }
    return DFW_PKG_PROCESS_RESULT_FORWARD;
}

dfwPkgProcessResult dfw_nat_dnat_process(struct rte_ipv4_hdr *ipv4_hdr) {
    assert(ipv4_hdr);

    struct rte_tcp_hdr *tcp_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp_hdr = (struct rte_tcp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
    } else if(ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        udp_hdr = (struct rte_udp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
    } else {
        /* only support tcp and udp */
        return DFW_PKG_PROCESS_RESULT_DROP;
    }

     /* DNAT */
    dfwDnatKey key;
    key.protocol = ipv4_hdr->next_proto_id;
    key.remote_ip = ipv4_hdr->src_addr;
    key.wan_ip = ipv4_hdr->dst_addr;
    
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        key.wan_port = tcp_hdr->dst_port;
        key.remote_port = tcp_hdr->src_port;
    } else if(ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        key.wan_port = udp_hdr->dst_port;
        key.remote_port = udp_hdr->src_port;
    }

    dfwNatEntry *nat_entry = NULL;
    if(rte_hash_lookup_data(dfw_ctx->dfw_nat_conf.dnat_table, 
                            (void *)&key, (void **)&nat_entry) < 0) {
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    assert(nat_entry);
    rte_atomic64_set(&nat_entry->last_seen_tsc, (int64_t)rte_get_tsc_cycles());
    ipv4_hdr->dst_addr = nat_entry->lan_ip;
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp_hdr->dst_port = nat_entry->lan_port;
        tcp_hdr->cksum = 0;
    } else if(ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        udp_hdr->dst_port = nat_entry->lan_port;
        udp_hdr->dgram_cksum = 0;
    }
    return DFW_PKG_PROCESS_RESULT_FORWARD;
}

void dfw_nat_contorl(void) {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    uint64_t now = rte_get_tsc_cycles();
    if(now < dfw_ctx->dfw_nat_conf.nat_next_scan_time_tsc) return;
    dfw_ctx->dfw_nat_conf.nat_next_scan_time_tsc = 
        now + ms_to_tsc(dfw_ctx->dfw_nat_conf.nat_scan_time_ms);

    void *key = NULL;
    void *val = NULL;
    dfwSnatKey free_snat_keys[DFW_BUF_SZ_1K] = {0};
    int free_snat_keys_idx = 0;
    dfwDnatKey free_dnat_keys[DFW_BUF_SZ_1K];
    int free_dnat_keys_idx = 0;
    uint32_t iter = 0;
    uint64_t nat_entry_avail_time_tsc = ms_to_tsc(dfw_ctx->dfw_nat_conf.nat_entry_avail_time_s * 1000);
    while(rte_hash_iterate(dfw_ctx->dfw_nat_conf.dnat_table, 
                           (const void **)&key, (void **)&val, &iter) >= 0)  {
        dfwNatEntry *nat_entry = (dfwNatEntry *)val;
        if(!nat_entry) continue;
        uint64_t last_seen_tsc = (uint64_t)rte_atomic64_read(&nat_entry->last_seen_tsc);
        if((nat_entry->state == DFW_NAT_ENTRY_ALIVE) && now - last_seen_tsc > nat_entry_avail_time_tsc) {
            if(free_dnat_keys_idx >= DFW_BUF_SZ_1K) break;
            nat_entry->dead_tsc = now;
            nat_entry->state = DFW_NAT_ENTRY_DYING;
            TAILQ_INSERT_TAIL(&dfw_ctx->dfw_nat_conf.nat_entry_free_list, 
                              nat_entry, delay_node);
            rte_memcpy((char *)&free_dnat_keys[free_dnat_keys_idx++], 
                        (char *)key, sizeof(dfwDnatKey));   
        }
    }

    iter = 0;
    while(rte_hash_iterate(dfw_ctx->dfw_nat_conf.snat_table,
                           (const void **)&key, (void **)&val, &iter) >= 0) {
        dfwNatEntry *nat_entry = (dfwNatEntry *)val;
        if(!nat_entry) continue;
        if(nat_entry->state == DFW_NAT_ENTRY_DYING) {
            if(free_snat_keys_idx >= DFW_BUF_SZ_1K) break;
            rte_memcpy((char *)&free_snat_keys[free_snat_keys_idx++],
                        (char *)key, sizeof(dfwSnatKey));
        }
    }

    
    for(int i = 0; i < free_dnat_keys_idx; ++i) {
        rte_hash_del_key(dfw_ctx->dfw_nat_conf.dnat_table, (const void *)&free_dnat_keys[i]);
    }
    for(int i = 0; i < free_snat_keys_idx; ++i) {
        rte_hash_del_key(dfw_ctx->dfw_nat_conf.snat_table, (const void *)&free_snat_keys[i]);
    }

    uint64_t dead_tsc_time = ms_to_tsc(dfw_ctx->dfw_nat_conf.nat_entry_dead_free_time_ms);
    dfwNatEntry *entry = NULL;
    while (!TAILQ_EMPTY(&dfw_ctx->dfw_nat_conf.nat_entry_free_list)) {
        entry = TAILQ_FIRST(&dfw_ctx->dfw_nat_conf.nat_entry_free_list);
        if (now - entry->dead_tsc < dead_tsc_time)
            break;

        TAILQ_REMOVE(&dfw_ctx->dfw_nat_conf.nat_entry_free_list, entry, delay_node);
        rte_free(entry);
    }

    return;
}