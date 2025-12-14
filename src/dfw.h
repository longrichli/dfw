#ifndef __DFW_H__
#define __DFW_H__

#include "dfw_log.h"
#include "dfw_nat.h"
#include "dfw_arp.h"
#include "dfw_acl.h"
#include <rte_mempool.h>
#include <rte_ip_frag.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_lpm.h>
#include <pthread.h>
#define DFW_BUF_SZ_64B
#define DFW_BUF_SZ_256B              (256)
#define DFW_BUF_SZ_1K                 (1024)
#define DFW_BUF_SZ_4K                 (4096)
#define DFW_BUF_SZ_8K             (8192)

#define DFW_MAX_ROUTE_ENTRY             (1024)
#define DFW_ARP_ENTRY_EXPIRE_MS_DEFAULT        (30000) /* 30 seconds */
#define DFW_ARP_MAX_RETRY_DEFAULT       (3)
#define DFW_ARP_MAX_PENDING_DEFAULT     (256)
#define DFW_ARP_RETRY_INTERVAL_MS_DEFAULT (1000)
#define DFW_ARP_ENTRY_DEAD_TIME_MS_DEFAULT (100)
#define DFW_ARP_SCAN_MS                 (500)

#define DFW_ENABLE_NAT_DEFAULT          (1)
#define DFW_NAT_ENTRY_AVAIL_TIME_S_DEFAULT (300)
#define DFW_NAT_ENTRY_DEAD_TIME_MS_DEFAULT (100)
#define DFW_NAT_SCAN_MS                     (500)



#define DFW_LOG_FILE_PATH_DEFAULT "../log/dfw.log"
#define DFW_CONF_FILE_PATH_DEFAULT "../config/common_cfg.json"
#define DFW_ROUTE_TBL_PATH_DEFAULT "../config/route_tbl.json"
#define DFW_ETH_CONF_PATH_DEFAULT "../config/eth_cfg.json"
#define DFW_ACL_CONF_PATH_DEFAULT "../config/acl_cfg.json"

#define MEMPOOL_CACHE_SIZE              (256)
#define MEMPOOL_MBUF_NUMS               (4095)
#define RX_DESC_DEFAULT                 (1024)
#define TX_DESC_DEFAULT                 (1024)
#define ETH_RX_QUEUE_DEFAULT            (1)
#define ETH_TX_QUEUE_DEFAULT            (1)
#define ETH_MTU_DEFAULT                 (1500)
#define ETH_ENABLE_ETH_PORT_MASK_DEFAULT     (3)
#define MAX_PKT_BURST                   (32)
#define MAX_PORT_QUEUE_MAP_PRE_LCORE    (32)
#define RX_LCORE_NUM_DEFAULT            (1)
#define TX_LCORE_NUM_DEFAULT            (1)
#define PROCESS_LCORE_NUM_DEFAULT       (1)
#define RING_ELEM_COUNT_DEFAULT        (1024)
#define IP_FRAG_TBL_BUCKET_NUM_DEFAULT (0x1000)
#define IP_FRAG_TBL_BUCKET_ENTRIES_DEFAULT (16)
#define IP_FRAG_TBL_MAX_ENTYIES_DEFAULT (0x1000)
#define IP_FRAG_TAL_MAX_FLOW_TTL        (1000)
#define PREFETCH_OFFSET                 (3)
#define BURST_TX_DRAIN_US              (100)

typedef enum _dfw_eth_port_type {
    DFW_ETH_PORT_TYPE_WAN = 0,
    DFW_ETH_PORT_TYPE_LAN,
    DFW_ETH_PORT_TYPE_WAN_BACKUP,
    DFW_ETH_PORT_TYPE_DMZ
} dfwEthPortType;

typedef struct _dfw_eth_port_entry {
    uint16_t port_id;
    char eth_name[RTE_ETH_NAME_MAX_LEN];
    char eth_pci[RTE_ETH_NAME_MAX_LEN];
    struct rte_ether_addr eth_mac;
    dfwEthPortType eth_port_type;
    uint32_t ip;
    uint32_t ipmask;
    uint32_t gateway;
} dfwEthPortEntry;

typedef struct _dfw_route_entry{
    uint32_t destination;
    uint32_t netmask;
    uint32_t gateway;
    char out_port[RTE_ETH_NAME_MAX_LEN];
    int metric;
} dfwRouteEntry;


typedef enum _dfw_msg_type {
    DFW_MSG_CREATE_ARP_ENTRY = 0,
    DFW_MSG_FLASH_ARP_PENDING,
    DFW_MSG_CREATE_NAT_ENTRY,
} dfwMsgType;

typedef struct _dfw_comm_msg {
    dfwMsgType msg_type;
    void *msg_content;
} dfwCommMsg;
typedef struct _dfw_context {
    struct rte_mempool *mempool;
    uint16_t eth_port_count;
    uint16_t eth_nb_rx_queue;
    uint16_t eth_nb_tx_queue;
    uint16_t eth_rx_desc_num;
    uint16_t eth_tx_desc_num;
    uint16_t eth_mtu;
    uint32_t enable_eth_port_mask;

    struct {
        uint8_t enable_nat;
        uint16_t nat_entry_avail_time_s;
        uint16_t nat_scan_time_ms;
        uint16_t nat_entry_dead_free_time_ms;
        uint64_t nat_port_alloc_hash_seed;
        uint64_t nat_next_scan_time_tsc;
        
        struct dfwNatDelayHead nat_entry_free_list;
        struct rte_hash *snat_table;
        struct rte_hash *dnat_table;
    } dfw_nat_conf;

    struct {
        struct rte_hash *arp_table;
        struct dfwArpDelayHead arp_entry_free_list;
        uint64_t arp_next_scan_time;
        uint16_t arp_entry_dead_free_time_ms;
        uint16_t arp_entry_expire_ms;
        uint16_t arp_entry_max_retry;
        uint16_t arp_entry_max_pending;
        uint16_t arp_retry_interval_ms;
        uint16_t arp_scan_time_ms;
       
    } dfw_arp_conf;

    struct {
        dfwAclTable acl_tables[2];
        _Atomic dfwAclTable *active_acl;
    } dfw_acl_conf;

    struct {
        char logfile_path[DFW_BUF_SZ_1K];
        char cfgfile_path[DFW_BUF_SZ_1K];
        char ethfile_path[DFW_BUF_SZ_1K];
        char routefile_path[DFW_BUF_SZ_1K];
        char aclfile_path[DFW_BUF_SZ_1K];
        logLevel log_level;
    } dfw_config;

    struct {
        uint16_t eth_port_entry_count;
        dfwEthPortEntry eth_port_entry[RTE_MAX_ETHPORTS];
        dfwEthPortEntry* eth_port_mapping[RTE_MAX_ETHPORTS];
    } dfw_eth_port_conf;


    struct {
        int route_entry_count;
        dfwRouteEntry route_entries[DFW_MAX_ROUTE_ENTRY];
        struct rte_lpm *lpm4;
    } dfw_route_conf;

    struct {
        uint8_t rx_lcore_num;
        unsigned int rx_lcore_ids[RTE_MAX_LCORE];
        uint8_t tx_lcore_num;
        unsigned int tx_lcore_ids[RTE_MAX_LCORE];
        uint8_t process_lcore_num;
        unsigned int process_lcore_ids[RTE_MAX_LCORE];
    } dfw_lcore_conf;

    struct {
        int idx;
        struct {
            uint16_t port_id;
            uint16_t queue_id;
        } pq_map[MAX_PORT_QUEUE_MAP_PRE_LCORE];
    } rx_port_queue_mapping[RTE_MAX_LCORE], tx_port_queue_mapping[RTE_MAX_LCORE];

    struct {
        struct rte_ring **tx_queue_rings[RTE_MAX_ETHPORTS];
        struct rte_ring **process_rings;
        struct rte_ring *msg_from_proc_lcore;
        unsigned int ring_elem_count;

    } dfw_ring_conf;

    struct {
        struct rte_ip_frag_tbl **frag_tables;
        struct rte_ip_frag_death_row *death_rows;
        uint32_t buckut_num;
        uint32_t bucket_entries;
        uint32_t max_entries;
    } dfw_ipfrag_conf;
    

    int is_loop;

} dfwContext;

dfwContext *dfw_context_instance(void);

void dfw_context_destory();

#endif /* __DFW_H__ */