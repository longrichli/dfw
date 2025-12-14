#include "dfw_arp.h"
#include "dfw_tools.h"
#include "dfw.h"
#include "dfw_flow.h"

#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_jhash.h>
#include <rte_lcore.h>
#include <rte_arp.h>


static const char DIGITS_LUT[200] = {
    "00010203040506070809"
    "10111213141516171819"
    "20212223242526272829"
    "30313233343536373839"
    "40414243444546474849"
    "50515253545556575859"
    "60616263646566676869"
    "70717273747576777879"
    "80818283848586878889"
    "90919293949596979899"
};

static inline char* u32_to_str(uint32_t value, char *buf) {
    char *p = buf;

    if (value >= 100000000) {
        uint32_t a = value / 100000000;
        uint32_t b = value % 100000000;

        if (a >= 10) {
            memcpy(p, &DIGITS_LUT[a * 2], 2); p += 2;
        } else {
            *p++ = '0' + a;
        }
        value = b;
    }

    if (value >= 1000000) {
        uint32_t a = value / 1000000;
        memcpy(p, &DIGITS_LUT[a * 2], 2); p += 2;
        value %= 1000000;
    }

    if (value >= 10000) {
        uint32_t a = value / 10000;
        memcpy(p, &DIGITS_LUT[a * 2], 2); p += 2;
        value %= 10000;
    }

    if (value >= 100) {
        uint32_t a = value / 100;
        memcpy(p, &DIGITS_LUT[a * 2], 2); p += 2;
        value %= 100;
    }

    if (value >= 10) {
        memcpy(p, &DIGITS_LUT[value * 2], 2);
        p += 2;
    } else {
        *p++ = '0' + value;
    }

    *p = '\0';
    return p;
}



dfwArpEntry *dfw_arp_entry_create(dfwContext *dfw_ctx, uint32_t ip, 
                                  uint16_t out_port, struct rte_ether_addr *src_mac) {
    assert(dfw_ctx);
    dfwArpEntry *arp_entry = rte_malloc("dfwArpEntry", sizeof(dfwArpEntry), 0);
    if(!arp_entry) {
        return NULL;
    }
    
    uint64_t tsc = rte_get_tsc_cycles();
    char ring_name[DFW_BUF_SZ_64B] = {0};
    char *p = NULL;
    
    arp_entry->expire_tsc = 
        tsc + ms_to_tsc(dfw_ctx->dfw_arp_conf.arp_entry_expire_ms);
    arp_entry->next_retry_tsc = 
        tsc + ms_to_tsc(dfw_ctx->dfw_arp_conf.arp_retry_interval_ms);
    arp_entry->retry = 0;
    p = u32_to_str(ip, ring_name);
    strcat(p - 1, "arp_ety");
    arp_entry->pending = rte_ring_create(ring_name, 
        dfw_ctx->dfw_arp_conf.arp_entry_max_pending,
        rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
    if(!arp_entry->pending) {
        rte_free(arp_entry);
        return NULL;
    }
    arp_entry->out_port = out_port;
    rte_memcpy(arp_entry->src_mac.addr_bytes, src_mac->addr_bytes, RTE_ETHER_ADDR_LEN);
    arp_entry->state = ARP_RESOLVING;
    arp_entry->ip = ip;
    rte_spinlock_init(&arp_entry->lock);
    return arp_entry;
}

int dfw_arp_create_msg_process(dfwArpCreateMsg *msg) {
    assert(msg);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    dfwArpEntry *arp_entry =  NULL;
    if(rte_hash_lookup_data(dfw_ctx->dfw_arp_conf.arp_table, 
                            &msg->ip, 
                            (void **)&arp_entry) < 0) {
        arp_entry = dfw_arp_entry_create(dfw_ctx, msg->ip, msg->portid, &msg->port_mac);
    }
    if(arp_entry) {

        rte_ring_sp_enqueue(arp_entry->pending, (void *)msg->mbuf);
    }

    return 0; 
}

int dfw_arp_flash_arp_pending_process(uint32_t ip) {
    dfwArpEntry *arp_entry = NULL;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    if(rte_hash_lookup_data(dfw_ctx->dfw_arp_conf.arp_table, 
        (void *)&ip, (void **)&arp_entry) >= 0) {
        return dfw_arp_flash_arp_pending(arp_entry);
    }
    return 0;
}

void dfw_update_arp_entry(uint32_t ip, struct rte_ether_addr *addr) {
    assert(addr);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    uint64_t tsc = rte_get_tsc_cycles();
    uint64_t expire_tsc = ms_to_tsc(dfw_ctx->dfw_arp_conf.arp_entry_expire_ms);
    dfwArpEntry *arp_entry = NULL;
    if(rte_hash_lookup_data(dfw_ctx->dfw_arp_conf.arp_table, &ip, (void **)&arp_entry) < 0) {
        return;
    }

    rte_spinlock_lock(&arp_entry->lock);
    arp_entry->ip = ip;
    arp_entry->state = ARP_RESOLVED;
    arp_entry->expire_tsc = 
        tsc + expire_tsc;
    rte_memcpy(arp_entry->dst_mac.addr_bytes, addr->addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_spinlock_unlock(&arp_entry->lock);
}

int dfw_arp_is_request_my_ip(uint32_t ip, uint16_t *out_port) {
    assert(out_port);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    for(int i = 0; i < dfw_ctx->dfw_eth_port_conf.eth_port_entry_count; ++i) {
        dfwEthPortEntry *eth_port_entry = 
            &dfw_ctx->dfw_eth_port_conf.eth_port_entry[i];
        if(eth_port_entry->ip == ip) {
            *out_port = eth_port_entry->port_id;
            return 1;
        }
    }
    return 0;
}

void dfw_arp_entry_free(dfwArpEntry *arp_entry) {
    if(!arp_entry) return;
    rte_spinlock_lock(&arp_entry->lock);
    if(arp_entry->pending) {
        struct rte_mbuf *mbuf = NULL;
        while(rte_ring_sc_dequeue(arp_entry->pending, (void **)&mbuf) == 0) {
            rte_pktmbuf_free(mbuf);
        }
        rte_ring_free(arp_entry->pending);
    }
    rte_spinlock_unlock(&arp_entry->lock);
    rte_free(arp_entry);  
}

dfwArpEntry *dfw_arp_table_lookup(uint32_t next_hop_ip) {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfwArpEntry *arp_entry = NULL;
    if(rte_hash_lookup_data(
            dfw_ctx->dfw_arp_conf.arp_table, 
            (void *)&next_hop_ip, (void **)&arp_entry) < 0) {
        return NULL;
    }
    return arp_entry;
}
int dfw_send_arp_pending_flash_msg(uint32_t ip) {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfwCommMsg *msg = rte_malloc("dfwCommMsg", sizeof(dfwCommMsg), 0);
    if (!msg) {
        return -1;
    }
    msg->msg_type = DFW_MSG_FLASH_ARP_PENDING;
    msg->msg_content = rte_malloc("u32Ip", sizeof(uint32_t), 0);
    if(!msg->msg_content) {
        rte_free(msg);
        return -1;
    }
    *(uint32_t *)msg->msg_content = ip;
    if (rte_ring_mp_enqueue(dfw_ctx->dfw_ring_conf.msg_from_proc_lcore, msg) < 0) {
        rte_free(msg->msg_content);
        rte_free(msg);
        return -1;
    }
    return 0;
}

int dfw_send_arp_entry_create_msg(uint32_t ip, 
                                  uint16_t portid, 
                                  struct rte_ether_addr *src_mac,
                                  struct rte_mbuf *mbuf)
{
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    struct rte_mbuf *mbuf_clone = rte_pktmbuf_clone(mbuf, dfw_ctx->mempool);
    if (mbuf_clone == NULL) {
        return -1;
    }

    dfwCommMsg *msg = rte_malloc("dfwCommMsg", sizeof(dfwCommMsg), 0);
    if (!msg) {
        rte_pktmbuf_free(mbuf_clone);
        return -1;
    }

    dfwArpCreateMsg *arp_msg = rte_malloc("dfwArpCreateMsg", sizeof(dfwArpCreateMsg), 0);
    if (!arp_msg) {
        rte_free(msg);
        rte_pktmbuf_free(mbuf_clone);
        return -1;
    }

    arp_msg->ip = ip;
    arp_msg->portid = portid;
    rte_memcpy(arp_msg->port_mac.addr_bytes, src_mac->addr_bytes, RTE_ETHER_ADDR_LEN);
    arp_msg->mbuf = mbuf_clone;

    msg->msg_type = DFW_MSG_CREATE_ARP_ENTRY;
    msg->msg_content = arp_msg;

    if (rte_ring_mp_enqueue(dfw_ctx->dfw_ring_conf.msg_from_proc_lcore, msg) < 0) {
        rte_pktmbuf_free(mbuf_clone);
        rte_free(arp_msg);
        rte_free(msg);
        return -1;
    }
    return 0;
}


int dfw_append_mbuf_to_pending(struct rte_mbuf *mbuf, dfwArpEntry *arp_entry) {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    assert(arp_entry);
    struct rte_mbuf *mbuf_clone = rte_pktmbuf_clone(mbuf, dfw_ctx->mempool);
    if (mbuf_clone == NULL) {
        return -1;
    }
    if(rte_ring_mp_enqueue(arp_entry->pending, (void *)mbuf_clone) < 0) {
        rte_pktmbuf_free(mbuf_clone);
        return -1;
    }
    return 0;
}

static int dfw_arp_send_arp_pkt(struct rte_ether_addr *arp_sa,
                            struct rte_ether_addr *arp_da,
                            uint32_t arp_sip, uint32_t arp_dip,
                            struct rte_ether_addr *eth_sa,
                            struct rte_ether_addr *eth_da,
                            uint16_t arp_opcode, uint16_t out_port) {
    assert(arp_sa && arp_da && eth_da);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(dfw_ctx->mempool);
    if(!mbuf) {
        return 0;
    }
    if(rte_pktmbuf_append(mbuf, sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr)) == NULL) {
        rte_pktmbuf_free(mbuf);
        return 0;
    }
    
    struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    ether_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
    rte_memcpy(ether_hdr->src_addr.addr_bytes, eth_sa->addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(ether_hdr->dst_addr.addr_bytes, eth_da->addr_bytes, RTE_ETHER_ADDR_LEN);
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(ether_hdr + 1);
    arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp_hdr->arp_hlen = 0x6;
    arp_hdr->arp_plen = 0x4;
    arp_hdr->arp_opcode = rte_cpu_to_be_16(arp_opcode);
    arp_hdr->arp_data.arp_sip = arp_sip;
    arp_hdr->arp_data.arp_tip = arp_dip;
    rte_memcpy(arp_hdr->arp_data.arp_sha.addr_bytes, 
               arp_sa->addr_bytes, 
               RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp_hdr->arp_data.arp_tha.addr_bytes, 
               arp_da->addr_bytes, 
               RTE_ETHER_ADDR_LEN);
    uint16_t txq = (arp_dip % dfw_ctx->eth_nb_tx_queue);
    struct rte_ring *tx_ring = 
                dfw_ctx->dfw_ring_conf.tx_queue_rings[out_port][txq];
    if(rte_ring_mp_enqueue(tx_ring, (void *)mbuf) < 0) {
        rte_pktmbuf_free(mbuf);
    }
    return 0;
}

int dfw_arp_send_arp_reply(struct rte_mbuf *mbuf, uint16_t portid) {
    assert(mbuf);
    struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr*);
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(ether_hdr + 1);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    return dfw_arp_send_arp_pkt(&ether_hdr->dst_addr, 
                                &ether_hdr->src_addr,
                                arp_hdr->arp_data.arp_tip,
                                arp_hdr->arp_data.arp_sip,
                                &dfw_ctx->dfw_eth_port_conf.eth_port_mapping[portid]->eth_mac,
                                &ether_hdr->src_addr, RTE_ARP_OP_REPLY, portid);
}

int dfw_arp_send_arp_request(dfwArpEntry *arp_entry) {
    assert(arp_entry);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    struct rte_ether_addr eth_da, arp_da;
    memset(eth_da.addr_bytes, 0xFF, RTE_ETHER_ADDR_LEN);
    memset(arp_da.addr_bytes, 0x00, RTE_ETHER_ADDR_LEN);
    return dfw_arp_send_arp_pkt(&arp_entry->src_mac, &arp_da, 
                                dfw_ctx->dfw_eth_port_conf.
                                eth_port_mapping[arp_entry->out_port]->ip,
                                arp_entry->ip, &arp_entry->src_mac,
                                &eth_da, RTE_ARP_OP_REQUEST, arp_entry->out_port);
    
}

void dfw_arp_control(void) {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    uint64_t now = rte_get_tsc_cycles();
    if(now < dfw_ctx->dfw_arp_conf.arp_next_scan_time) return;
    dfw_ctx->dfw_arp_conf.arp_next_scan_time = 
        now + ms_to_tsc(dfw_ctx->dfw_arp_conf.arp_scan_time_ms);
    
    uint32_t free_list[DFW_BUF_SZ_1K] = {0};
    int free_list_idx = 0;
    void *key = NULL;
    void *val = NULL;
    uint32_t iter = 0;
    while(rte_hash_iterate(dfw_ctx->dfw_arp_conf.arp_table, 
                           (const void **)&key, (void **)&val, &iter) >= 0) {
        dfwArpEntry *arp_entry = (dfwArpEntry *)val;
        if(!arp_entry) continue;
        rte_spinlock_lock(&arp_entry->lock);
        if(arp_entry->state == ARP_RESOLVED) {
            dfw_arp_flash_arp_pending(arp_entry);
            if(now > arp_entry->expire_tsc && free_list_idx < DFW_BUF_SZ_1K) {
                free_list[free_list_idx++] = *(uint32_t *)key;
                TAILQ_INSERT_TAIL(&dfw_ctx->dfw_arp_conf.arp_entry_free_list, arp_entry, delay_node);
                arp_entry->dead_tsc = now;
                arp_entry->state = ARP_FREE;
            }
        } else if(arp_entry->state == ARP_RESOLVING && now >= arp_entry->next_retry_tsc) {
            if(arp_entry->retry > dfw_ctx->dfw_arp_conf.arp_entry_max_retry &&
               free_list_idx < DFW_BUF_SZ_1K) {
               
                free_list[free_list_idx++] = *(uint32_t *)key;
                TAILQ_INSERT_TAIL(&dfw_ctx->dfw_arp_conf.arp_entry_free_list, arp_entry, delay_node);
                arp_entry->dead_tsc = now;
                arp_entry->state = ARP_FAILED;
                
                rte_spinlock_unlock(&arp_entry->lock);
                continue;
            }
            dfw_arp_send_arp_request(arp_entry);
            arp_entry->retry++;
            arp_entry->next_retry_tsc = 
                now + ms_to_tsc(dfw_ctx->dfw_arp_conf.arp_retry_interval_ms);
        }
        rte_spinlock_unlock(&arp_entry->lock);
    }

    /* 移除需要释放的arp entry */
    for(int i = 0; i < free_list_idx; i++) {
        rte_hash_del_key(dfw_ctx->dfw_arp_conf.arp_table, &free_list[i]);
    } 

    uint64_t dead_tsc_time = ms_to_tsc(dfw_ctx->dfw_arp_conf.arp_entry_dead_free_time_ms);
    dfwArpEntry *entry = NULL;
    while (!TAILQ_EMPTY(&dfw_ctx->dfw_arp_conf.arp_entry_free_list)) {
        entry = TAILQ_FIRST(&dfw_ctx->dfw_arp_conf.arp_entry_free_list);
        if (now - entry->dead_tsc < dead_tsc_time)
            break;

        TAILQ_REMOVE(&dfw_ctx->dfw_arp_conf.arp_entry_free_list, entry, delay_node);
        rte_free(entry);
    }

}

int dfw_arp_flash_arp_pending(dfwArpEntry *arp_entry) {
    assert(arp_entry);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    struct rte_mbuf *pkt_mbufs[MAX_PKT_BURST] = {0};
    unsigned int nb_pkt = 0;
    
    while((nb_pkt = rte_ring_sc_dequeue_burst(arp_entry->pending, 
                                    (void **)pkt_mbufs,
                                    MAX_PKT_BURST, NULL)) > 0) {
        for(unsigned int i = 0; i < nb_pkt; i++) {
            /* 更新 mac 地址 */
            /* 修改以太网头部 + TCP + mbuf */
            struct rte_mbuf *mbuf = pkt_mbufs[i];
            struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            struct rte_ipv4_hdr *ipv4_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
            rte_memcpy(&ether_hdr->dst_addr.addr_bytes, arp_entry->dst_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
            rte_memcpy(&ether_hdr->src_addr.addr_bytes, arp_entry->src_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
            ipv4_hdr->time_to_live -= 1;
            ipv4_hdr->hdr_checksum = 0;
            mbuf->l2_len = sizeof(struct rte_ether_hdr);
            mbuf->l3_len = (ipv4_hdr->version_ihl & 0x0F) << 2;
            mbuf->ol_flags |= (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM);
            uint32_t flow_hash = dfw_flow_key_hash_from_mbuf(mbuf);
            uint16_t queue_id = flow_hash % dfw_ctx->eth_nb_tx_queue;
                struct rte_ring *tx_ring = 
                    dfw_ctx->dfw_ring_conf.tx_queue_rings[arp_entry->out_port][queue_id];
                if(rte_ring_mp_enqueue(tx_ring, (void *)mbuf) < 0) {
                    rte_pktmbuf_free(mbuf);
                }
        }
    }
    return 0;
}