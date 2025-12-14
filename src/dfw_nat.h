#ifndef __DFW_NAT_H__
#define __DFW_NAT_H__

#include "dfw_pkg_proceesor.h"
#include <rte_ip.h>
#include <sys/queue.h>

typedef struct _dfw_snat_key {
    uint32_t lan_ip;
    uint32_t remote_ip;
    uint16_t lan_port;
    uint16_t remote_port;
    uint8_t protocol;
} __rte_packed dfwSnatKey;

typedef struct _dfw_dnat_key {
    uint32_t wan_ip;
    uint32_t remote_ip;
    uint16_t wan_port;
    uint16_t remote_port;
    uint8_t protocol;
} __rte_packed dfwDnatKey;

typedef enum _dfw_nat_entry_state {
    DFW_NAT_ENTRY_ALIVE = 0,
    DFW_NAT_ENTRY_DYING,
} dfwNatEntryState;

typedef struct _dwf_nat_entry {
    TAILQ_ENTRY(_dwf_nat_entry) delay_node;
    rte_atomic64_t last_seen_tsc;
    uint64_t dead_tsc;
    dfwNatEntryState state;

    uint32_t lan_ip;
    uint32_t wan_ip;

    uint16_t lan_port;
    uint16_t wan_port;

    uint8_t protocol;
} dfwNatEntry;

typedef struct _dfw_nat_create_msg {
    uint32_t lan_ip;
    uint32_t remote_ip;
    uint16_t lan_port;
    uint16_t remote_port;
    uint16_t out_port;
    uint8_t protocol;
} dfwNatCreateMsg;

TAILQ_HEAD(dfwNatDelayHead, _dwf_nat_entry);

int dfw_nat_create_msg_process(dfwNatCreateMsg *msg);

dfwPkgProcessResult dfw_nat_dnat_process(struct rte_ipv4_hdr *ipv4_hdr);

dfwPkgProcessResult dfw_nat_snat_process(struct rte_ipv4_hdr *ipv4_hdr, uint16_t out_port);

void dfw_nat_contorl(void);

#endif /* __DFW_NAT_H__ */