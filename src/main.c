#include "dfw_dpdk.h"
#include "dfw.h"
#include "dfw_arp.h"
#include "dfw_nat.h"
#include "dfw_pkg_proceesor.h"
#include "dfw_flow.h"
#include <stdlib.h>
#include <signal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_hash.h>

static void signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		dfw_log_write(LOG_INFO, "Signal %d received, preparing to exit...\n",
				signum);
        dfwContext *dfw_ctx = dfw_context_instance();
        assert(dfw_ctx);
		dfw_ctx->is_loop = false;
	}
}


int recv_msg_from_proc_lcore() {
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfwCommMsg *msg = NULL;
    while(rte_ring_sc_dequeue(dfw_ctx->dfw_ring_conf.msg_from_proc_lcore, 
                        (void **)&msg) == 0) {
        if(!msg) continue;
        if(msg->msg_type == DFW_MSG_CREATE_ARP_ENTRY) {
            dfw_arp_create_msg_process(msg->msg_content);
        } else if(msg->msg_type == DFW_MSG_FLASH_ARP_PENDING) {
            dfw_arp_flash_arp_pending_process(*(uint32_t *)msg->msg_content);
        } else if(msg->msg_type == DFW_MSG_CREATE_NAT_ENTRY) {
            dfw_nat_create_msg_process(msg->msg_content);
        }
        rte_free(msg->msg_content);
        rte_free(msg);
    }
    return 0;
}

int dfw_rx_loop(void *arg) {
    unsigned lcore_id = rte_lcore_id();
    int port_queue_map_sz = 0;
    struct rte_mbuf *pkt_burst[MAX_PKT_BURST];

    dfw_log_write(LOG_INFO, "dfw_rx_loop() started on lcore %u", lcore_id);
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    port_queue_map_sz = dfw_ctx->rx_port_queue_mapping[lcore_id].idx;
    if(port_queue_map_sz == 0) {
        dfw_log_write(LOG_INFO, "dfw_rx_loop() lcore %u has nothing to do", lcore_id);
        return 0;
    }
	
    while(dfw_ctx->is_loop) {

        for(int k = 0; k < port_queue_map_sz; ++k) {
            uint16_t portid = dfw_ctx->rx_port_queue_mapping[lcore_id]
                .pq_map[k].port_id;
            uint16_t queueid = dfw_ctx->rx_port_queue_mapping[lcore_id]
                .pq_map[k].queue_id;
            uint16_t nb_rx = 0;

            /* 处理 portid 的 queueid 上的数据包 */
            nb_rx = rte_eth_rx_burst(portid, queueid, pkt_burst, MAX_PKT_BURST);

            if(unlikely(nb_rx == 0)) {
                rte_pause();
                continue;
            }        
            
            for(int i = 0; i < nb_rx; ++i) {
                uint32_t flow_hash = 0;
                int process_ring_idx = 0;
                struct rte_ring *process_ring = NULL;
                if (likely(i + PREFETCH_OFFSET < nb_rx)) {
                    rte_prefetch0(rte_pktmbuf_mtod(pkt_burst[i + PREFETCH_OFFSET], void *));
                }
                flow_hash = dfw_flow_key_hash_from_mbuf(pkt_burst[i]);
                
                process_ring_idx = flow_hash % dfw_ctx->dfw_lcore_conf.process_lcore_num;
                process_ring = dfw_ctx->dfw_ring_conf.process_rings[process_ring_idx];
                assert(process_ring);

                if(unlikely(rte_ring_mp_enqueue(process_ring, (void *)pkt_burst[i]) < 0)) {
                    rte_pktmbuf_free(pkt_burst[i]);
                    dfw_log_write(LOG_WARNING, "dfw_rx_loop() rte_ring_enqueue_burst() drop a packet.");
                }    
            }
        }
    }

    return 0;
}

int dfw_tx_loop(void *arg) {
    
    unsigned int lcore_id = rte_lcore_id();
    int port_queue_map_sz = 0;
    struct rte_mbuf *pkt_burst[MAX_PKT_BURST];
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfw_log_write(LOG_INFO, "dfw_tx_loop() started on lcore %u", lcore_id);

    port_queue_map_sz = dfw_ctx->tx_port_queue_mapping[lcore_id].idx;
    if(port_queue_map_sz == 0) {
        dfw_log_write(LOG_INFO, "dfw_tx_loop() lcore %u has nothing to do", lcore_id);
        return 0;
    }

    while(dfw_ctx->is_loop) {
        for(int k = 0; k < port_queue_map_sz; ++k) {
            uint16_t portid = dfw_ctx->tx_port_queue_mapping[lcore_id]
                    .pq_map[k].port_id;
            uint16_t queueid = dfw_ctx->tx_port_queue_mapping[lcore_id]
                    .pq_map[k].queue_id;
            struct rte_ring *out_ring = 
                    dfw_ctx->dfw_ring_conf.tx_queue_rings[portid][queueid];
            assert(out_ring);
            uint16_t nb_pkt = 0;
            
            nb_pkt = rte_ring_sc_dequeue_burst(out_ring, (void **)pkt_burst, MAX_PKT_BURST, NULL);
            if(unlikely(nb_pkt == 0)) {
                rte_pause();
                continue;
            }

            uint16_t tx_done = 0;
            while (tx_done < nb_pkt) {

                uint16_t sent = rte_eth_tx_burst(
                    portid, queueid,
                    &pkt_burst[tx_done], nb_pkt - tx_done);

                tx_done += sent;

                if (sent == 0)
                    break;
            }

            for (uint16_t i = tx_done; i < nb_pkt; i++) {
                rte_pktmbuf_free(pkt_burst[i]);
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {

    dfwContext *dfw_ctx = NULL;
    unsigned int lcore_id = 0;
    uint16_t portid = 0;
    
   
    if(dfw_dpdk_init(argc, argv) < 0) {
        dfw_log_write(LOG_ERROR, "dpdk_init() error.");
        exit(EXIT_FAILURE);
    }
    signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

    dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    /* 启动RX处理线程 */
    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.rx_lcore_num; ++i) {
        lcore_id = dfw_ctx->dfw_lcore_conf.rx_lcore_ids[i];
        rte_eal_remote_launch(dfw_rx_loop, NULL, lcore_id);
    }
    /* 启动处理线程 */
    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.process_lcore_num; ++i) {
        lcore_id = dfw_ctx->dfw_lcore_conf.process_lcore_ids[i];
        rte_eal_remote_launch(dfw_pkg_process_loop, NULL, lcore_id);
    }

    /* 启动TX处理线程 */
    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.tx_lcore_num; ++i) {
        lcore_id = dfw_ctx->dfw_lcore_conf.tx_lcore_ids[i];
        rte_eal_remote_launch(dfw_tx_loop, NULL, lcore_id);
    }

    while(dfw_ctx->is_loop) {
        /* TODO 控制面处理 */
        recv_msg_from_proc_lcore();

        dfw_arp_control();
        dfw_nat_contorl();
    }
    
    /* 等待所有工作线程退出 */
    for (int i = 0; i < dfw_ctx->dfw_lcore_conf.rx_lcore_num; ++i) {
        lcore_id = dfw_ctx->dfw_lcore_conf.rx_lcore_ids[i];
        rte_eal_wait_lcore(lcore_id);
    }
    for (int i = 0; i < dfw_ctx->dfw_lcore_conf.process_lcore_num; ++i) {
        lcore_id = dfw_ctx->dfw_lcore_conf.process_lcore_ids[i];
        rte_eal_wait_lcore(lcore_id);
    }
    for (int i = 0; i < dfw_ctx->dfw_lcore_conf.tx_lcore_num; ++i) {
        lcore_id = dfw_ctx->dfw_lcore_conf.tx_lcore_ids[i];
        rte_eal_wait_lcore(lcore_id);
    }

    dfw_log_write(LOG_INFO, "exit...");
    RTE_ETH_FOREACH_DEV(portid) {
        if((dfw_ctx->enable_eth_port_mask & (1 << portid)) == 0) 
            continue;
        rte_eth_dev_stop(portid);
        rte_eth_dev_close(portid);
    }
    dfw_context_destory();
    rte_eal_cleanup();
    dfw_log_write(LOG_INFO, "exit done.");
    return 0;
}