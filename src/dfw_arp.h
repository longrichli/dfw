#ifndef __DFW_ARP_H__
#define __DFW_ARP_H__
#include <rte_ring.h>
#include <rte_ether.h>
#include <sys/queue.h>

typedef enum {
    ARP_FREE = 0,
    ARP_RESOLVING,    /* 正在等待 ARP reply */
    ARP_RESOLVED,     /* 有 MAC */
    ARP_FAILED        /* 多次 retry 失败 */
} dfwArpState;

typedef struct _dfw_arp_entry {
    uint32_t ip;                    /* next-hop IP */
    uint16_t out_port;              /* 对应出口 */
    struct rte_ether_addr src_mac;   /* 端口mac地址*/
    struct rte_ether_addr dst_mac;   /* 解析成功的 MAC */

    TAILQ_ENTRY(_dfw_arp_entry) delay_node;
    uint64_t dead_tsc;
    dfwArpState state;

    uint8_t retry;                  /* 重试次数 */
    uint64_t next_retry_tsc;        /* 下次 retry 的时间 */
    uint64_t expire_tsc;            /* aging 超时时间 */
    struct rte_ring *pending;       /* 存储等待发送的 mbuf* */

    rte_spinlock_t lock;            /* 保护 entry */
} dfwArpEntry;

typedef struct _dfw_arp_create_msg {
    uint32_t ip;
    uint16_t portid;
    struct rte_ether_addr port_mac;
    struct rte_mbuf *mbuf;
} dfwArpCreateMsg;

TAILQ_HEAD(dfwArpDelayHead, _dfw_arp_entry);

dfwArpEntry *dfw_arp_table_lookup(uint32_t next_hop_ip);

int dfw_send_arp_entry_create_msg(uint32_t ip, 
                                  uint16_t portid, 
                                  struct rte_ether_addr *src_mac,
                                  struct rte_mbuf *mbuf);

int dfw_append_mbuf_to_pending(struct rte_mbuf *mbuf, dfwArpEntry *arp_entry);

void dfw_arp_control(void);

int dfw_arp_send_arp_reply(struct rte_mbuf *mbuf, uint16_t portid);

int dfw_arp_create_msg_process(dfwArpCreateMsg *msg);

int dfw_arp_flash_arp_pending_process(uint32_t ip);

int dfw_arp_flash_arp_pending(dfwArpEntry *arp_entry);

void dfw_update_arp_entry(uint32_t ip, struct rte_ether_addr *addr);

int dfw_arp_is_request_my_ip(uint32_t ip, uint16_t *out_port);

int dfw_send_arp_pending_flash_msg(uint32_t ip);

#endif /* __DFW_ARP_H__ */