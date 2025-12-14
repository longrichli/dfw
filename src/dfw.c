#include "dfw.h"
#include "dfw_nat.h"
#include <stdlib.h>
#include <rte_ethdev.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <string.h>

static dfwContext *dfw_ctx = NULL;

static struct rte_hash_parameters arp_hash_parameters = {
    .name = "arp_table",
    .entries = 1024,
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .key_len = sizeof(uint32_t),
    .socket_id = 0,
    .extra_flag =
        RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF |
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
};


static struct rte_hash_parameters snat_hash_parameters = {
    .name = "snat_table",
    .entries = 1 << 16,
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .key_len = sizeof(dfwSnatKey),
    .socket_id = 0,
    .extra_flag =
        RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF |
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
};

static struct rte_hash_parameters dnat_hash_parameters = {
    .name = "dnat_table",
    .entries = 1 << 16,
    .hash_func = rte_jhash,
    .hash_func_init_val = 0,
    .key_len = sizeof(dfwDnatKey),
    .socket_id = 0, 
    .extra_flag =
        RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF |
        RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT,
};

dfwContext *dfw_context_instance(void) {
    if(dfw_ctx == NULL) {
        dfw_ctx = malloc(sizeof(dfwContext));
        if(!dfw_ctx) return NULL;
        memset(dfw_ctx, 0, sizeof(dfwContext));
        dfw_ctx->is_loop = true; 
        dfw_ctx->eth_nb_rx_queue = ETH_RX_QUEUE_DEFAULT;
        dfw_ctx->eth_nb_tx_queue = ETH_TX_QUEUE_DEFAULT;
        dfw_ctx->eth_rx_desc_num = RX_DESC_DEFAULT;
        dfw_ctx->eth_tx_desc_num = TX_DESC_DEFAULT;
        dfw_ctx->eth_mtu = ETH_MTU_DEFAULT;
        dfw_ctx->enable_eth_port_mask = ETH_ENABLE_ETH_PORT_MASK_DEFAULT;
        dfw_ctx->dfw_lcore_conf.rx_lcore_num = RX_LCORE_NUM_DEFAULT;
        dfw_ctx->dfw_lcore_conf.tx_lcore_num = TX_LCORE_NUM_DEFAULT;
        dfw_ctx->dfw_lcore_conf.process_lcore_num = PROCESS_LCORE_NUM_DEFAULT;
        dfw_ctx->dfw_ring_conf.ring_elem_count = RING_ELEM_COUNT_DEFAULT;
        dfw_ctx->dfw_ipfrag_conf.buckut_num = IP_FRAG_TBL_BUCKET_NUM_DEFAULT;
        dfw_ctx->dfw_ipfrag_conf.bucket_entries = IP_FRAG_TBL_BUCKET_ENTRIES_DEFAULT;
        dfw_ctx->dfw_ipfrag_conf.max_entries = IP_FRAG_TBL_MAX_ENTYIES_DEFAULT;
        arp_hash_parameters.socket_id = rte_socket_id();
        dfw_ctx->dfw_arp_conf.arp_table = rte_hash_create(&arp_hash_parameters);
        if(!dfw_ctx->dfw_arp_conf.arp_table) {
            dfw_log_write(LOG_ERROR, 
                "dfw_context_instance() rte_hash_create() error: can not create arp table.");
            free(dfw_ctx);
            return NULL;
        }
        dfw_ctx->dfw_arp_conf.arp_entry_expire_ms = 
            DFW_ARP_ENTRY_EXPIRE_MS_DEFAULT;
        dfw_ctx->dfw_arp_conf.arp_entry_max_pending = 
            DFW_ARP_MAX_PENDING_DEFAULT;
        dfw_ctx->dfw_arp_conf.arp_entry_max_retry =
            DFW_ARP_MAX_RETRY_DEFAULT;
        dfw_ctx->dfw_arp_conf.arp_retry_interval_ms =
            DFW_ARP_RETRY_INTERVAL_MS_DEFAULT;
        dfw_ctx->dfw_arp_conf.arp_entry_dead_free_time_ms =
            DFW_ARP_ENTRY_DEAD_TIME_MS_DEFAULT;
        dfw_ctx->dfw_arp_conf.arp_scan_time_ms = 
            DFW_ARP_SCAN_MS;
        dfw_ctx->dfw_arp_conf.arp_next_scan_time = 0;
        TAILQ_INIT(&dfw_ctx->dfw_arp_conf.arp_entry_free_list);
        dfw_ctx->dfw_nat_conf.enable_nat = DFW_ENABLE_NAT_DEFAULT;
        snat_hash_parameters.socket_id = rte_socket_id();
        dfw_ctx->dfw_nat_conf.snat_table = rte_hash_create(&snat_hash_parameters);
        if(!dfw_ctx->dfw_nat_conf.snat_table) {
            dfw_log_write(LOG_ERROR, 
            "dfw_context_instance() rte_hash_create() error: can not create snat table.");
            rte_hash_free(dfw_ctx->dfw_arp_conf.arp_table);
            free(dfw_ctx);
            return NULL;
        }
        dnat_hash_parameters.socket_id = rte_socket_id();
        dfw_ctx->dfw_nat_conf.dnat_table = rte_hash_create(&dnat_hash_parameters);
        if(!dfw_ctx->dfw_nat_conf.dnat_table) {
            dfw_log_write(LOG_ERROR, 
            "dfw_context_instance() rte_hash_create() error: can not create dnat table.");
            rte_hash_free(dfw_ctx->dfw_arp_conf.arp_table);
            rte_hash_free(dfw_ctx->dfw_nat_conf.snat_table);
            free(dfw_ctx);
            return NULL;
        }
        dfw_ctx->dfw_nat_conf.nat_port_alloc_hash_seed = rte_rand();
        dfw_ctx->dfw_nat_conf.nat_entry_avail_time_s = 
            DFW_NAT_ENTRY_AVAIL_TIME_S_DEFAULT;
        dfw_ctx->dfw_nat_conf.nat_entry_dead_free_time_ms = 
            DFW_NAT_ENTRY_DEAD_TIME_MS_DEFAULT;
        dfw_ctx->dfw_nat_conf.nat_scan_time_ms = 
            DFW_NAT_SCAN_MS;
        dfw_ctx->dfw_nat_conf.nat_next_scan_time_tsc = 0;
        TAILQ_INIT(&dfw_ctx->dfw_nat_conf.nat_entry_free_list);
        

        strcpy(dfw_ctx->dfw_config.cfgfile_path, DFW_CONF_FILE_PATH_DEFAULT);
        strcpy(dfw_ctx->dfw_config.ethfile_path, DFW_ETH_CONF_PATH_DEFAULT);
        strcpy(dfw_ctx->dfw_config.logfile_path, DFW_LOG_FILE_PATH_DEFAULT);
        strcpy(dfw_ctx->dfw_config.routefile_path, DFW_ROUTE_TBL_PATH_DEFAULT);
        strcpy(dfw_ctx->dfw_config.aclfile_path, DFW_ACL_CONF_PATH_DEFAULT);
        
        for (int i = 0; i < RTE_MAX_LCORE; ++i) {
            dfw_ctx->rx_port_queue_mapping[i].idx = 0;
            dfw_ctx->tx_port_queue_mapping[i].idx = 0;
        }
    }
    return dfw_ctx;
}

void dfw_context_destory() {
    if(dfw_ctx) {
        if(dfw_ctx->mempool) {
            rte_mempool_free(dfw_ctx->mempool);
            dfw_ctx->mempool = NULL;
        }
        for (int i = 0; i < dfw_ctx->dfw_lcore_conf.process_lcore_num; ++i) {
            if(dfw_ctx->dfw_ring_conf.process_rings &&
               dfw_ctx->dfw_ring_conf.process_rings[i]) {
                rte_ring_free(dfw_ctx->dfw_ring_conf.process_rings[i]);
                dfw_ctx->dfw_ring_conf.process_rings[i] = NULL;
            }
            if(dfw_ctx->dfw_ipfrag_conf.frag_tables &&
               dfw_ctx->dfw_ipfrag_conf.frag_tables[i]) {
                rte_ip_frag_table_destroy(dfw_ctx->dfw_ipfrag_conf.frag_tables[i]);
                dfw_ctx->dfw_ipfrag_conf.frag_tables[i] = NULL;
            }
        }
        if(dfw_ctx->dfw_ring_conf.process_rings) {
            free(dfw_ctx->dfw_ring_conf.process_rings);
            dfw_ctx->dfw_ring_conf.process_rings = NULL;
        }
        if(dfw_ctx->dfw_ipfrag_conf.frag_tables) {
            free(dfw_ctx->dfw_ipfrag_conf.frag_tables);
            dfw_ctx->dfw_ipfrag_conf.frag_tables = NULL;
        }
        if(dfw_ctx->dfw_ipfrag_conf.death_rows) {
            free(dfw_ctx->dfw_ipfrag_conf.death_rows);
            dfw_ctx->dfw_ipfrag_conf.death_rows = NULL;
        }

        if(dfw_ctx->dfw_arp_conf.arp_table) {
            rte_hash_free(dfw_ctx->dfw_arp_conf.arp_table);
            dfw_ctx->dfw_arp_conf.arp_table = NULL;
        }

        dfwArpEntry *arp_entry = NULL;
        while (!TAILQ_EMPTY(&dfw_ctx->dfw_arp_conf.arp_entry_free_list)) {
            arp_entry = TAILQ_FIRST(&dfw_ctx->dfw_arp_conf.arp_entry_free_list);
            TAILQ_REMOVE(&dfw_ctx->dfw_arp_conf.arp_entry_free_list, arp_entry, delay_node);
            rte_free(arp_entry);
        }
        if(dfw_ctx->dfw_nat_conf.snat_table) {
            rte_hash_free(dfw_ctx->dfw_nat_conf.snat_table);
            dfw_ctx->dfw_nat_conf.snat_table = NULL;
        }
        if(dfw_ctx->dfw_nat_conf.dnat_table) {
            rte_hash_free(dfw_ctx->dfw_nat_conf.dnat_table);
            dfw_ctx->dfw_nat_conf.dnat_table = NULL;
        }

        dfwNatEntry *nat_entry = NULL;
        while (!TAILQ_EMPTY(&dfw_ctx->dfw_nat_conf.nat_entry_free_list)) {
            nat_entry = TAILQ_FIRST(&dfw_ctx->dfw_nat_conf.nat_entry_free_list);
            TAILQ_REMOVE(&dfw_ctx->dfw_nat_conf.nat_entry_free_list, nat_entry, delay_node);
            rte_free(nat_entry);
        }
    

        uint16_t portid;
        RTE_ETH_FOREACH_DEV(portid) {
            if((dfw_ctx->enable_eth_port_mask & (1 << portid)) == 0)
                continue;
            if(dfw_ctx->dfw_ring_conf.tx_queue_rings[portid]) {
                for(int q = 0; q < dfw_ctx->eth_nb_tx_queue; ++q) {
                    if(dfw_ctx->dfw_ring_conf.tx_queue_rings[portid][q]) {
                        rte_ring_free(dfw_ctx->dfw_ring_conf.tx_queue_rings[portid][q]);
                        dfw_ctx->dfw_ring_conf.tx_queue_rings[portid][q] = NULL;
                    }
                }
                free(dfw_ctx->dfw_ring_conf.tx_queue_rings[portid]);
                dfw_ctx->dfw_ring_conf.tx_queue_rings[portid] = NULL;
            }
        }

        if(dfw_ctx->dfw_ring_conf.msg_from_proc_lcore) {
            rte_ring_free(dfw_ctx->dfw_ring_conf.msg_from_proc_lcore);
            dfw_ctx->dfw_ring_conf.msg_from_proc_lcore = NULL;
        }


        free(dfw_ctx);
        dfw_ctx = NULL;
    }
}

