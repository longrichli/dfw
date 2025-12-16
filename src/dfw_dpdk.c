#include "dfw_dpdk.h"
#include "dfw.h"
#include "dfw_cfg.h"
#include <rte_eal.h>
#include <stdlib.h>
#include <rte_mbuf.h>
#include <rte_ethdev.h>
#include <rte_dev.h>
#include <rte_ip_frag.h>


static struct rte_eth_conf port_conf = {
    
    .rxmode = {
        .mq_mode = RTE_ETH_MQ_RX_RSS,
        .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP,
        },
    },
};




static int dfw_port_init(uint16_t portid) {
    int ret = -1;
    int tmp_ret = -1;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_rxconf *rxconf = NULL;
    struct rte_eth_txconf *txconf = NULL;
    struct rte_ether_addr addr;
    struct rte_eth_dev_info dev_info;

    /* 检查端口是否有效 */
    if (!rte_eth_dev_is_valid_port(portid))
        return -1;

    if(rte_eth_dev_info_get(portid, &dev_info) < 0) {
        dfw_log_write(LOG_ERROR, "dfw_port_init() rte_eth_dev_info_get() Error getting device info for port %u", 
               portid);
        goto __finish;
    }

    /* 配置设备 */
    tmp_ret = rte_eth_dev_configure(portid, dfw_ctx->eth_nb_rx_queue, dfw_ctx->eth_nb_tx_queue, &local_port_conf);
    if (tmp_ret != 0) {
        dfw_log_write(LOG_ERROR, "dfw_port_init() rte_eth_dev_configure() error. portid[%u]", portid);
        goto __finish;
    }

    /* 调整rx，tx 描述符数量*/
    tmp_ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &dfw_ctx->eth_nb_rx_queue,
						       &dfw_ctx->eth_nb_tx_queue);
    if(tmp_ret < 0) {
        dfw_log_write(LOG_ERROR, "dfw_port_init() rte_eth_dev_adjust_nb_rx_tx_desc()"
             "Cannot adjust number of descriptors: %u", 
               portid);
        goto __finish;
    }

    /* 设置RX队列 */
    rxconf = &dev_info.default_rxconf;
    rxconf->offloads |=
    local_port_conf.rxmode.offloads;
    for(int i = 0; i < dfw_ctx->eth_nb_rx_queue; ++i) {
        fflush(stdout);
        tmp_ret = rte_eth_rx_queue_setup(portid, i, dfw_ctx->eth_rx_desc_num,
        rte_eth_dev_socket_id(portid), rxconf, dfw_ctx->mempool);
        if (tmp_ret < 0) {
            dfw_log_write(LOG_ERROR, "dfw_port_init() rte_eth_rx_queue_setup() Error setting up RX queue for port %u, queue: %d", 
                portid, i);
            goto __finish;
        }
    }
    
    /* 设置TX队列 */
    txconf = &dev_info.default_txconf;
    txconf->offloads |=
    local_port_conf.txmode.offloads;
    for(int i = 0; i < dfw_ctx->eth_nb_tx_queue; ++i) {
        fflush(stdout);
        tmp_ret = rte_eth_tx_queue_setup(portid, i, dfw_ctx->eth_tx_desc_num,
                rte_eth_dev_socket_id(portid), txconf);
        if (tmp_ret < 0) {
            dfw_log_write(LOG_ERROR, "dfw_port_init() rte_eth_tx_queue_setup() Error setting up TX queue for port %u", 
                portid);
            goto __finish;
        }
    }
    /* 启动设备 */
    tmp_ret = rte_eth_dev_start(portid);
    if (tmp_ret < 0) {
        dfw_log_write(LOG_ERROR, "dfw_port_init() rte_eth_dev_start() Error starting port %u", portid);
        goto __finish;
    }

    /* 设置 mtu */
    tmp_ret = rte_eth_dev_set_mtu(portid, dfw_ctx->eth_mtu);
    if (tmp_ret < 0) {
        dfw_log_write(LOG_ERROR, "dfw_port_init() rte_eth_dev_set_mtu() Error set port %u mtu.", portid);
        goto __finish;
    }

    /* 获取并显示MAC地址 */
    tmp_ret = rte_eth_macaddr_get(portid, &addr);
    if (tmp_ret != 0) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_eth_macaddr_get() Error getting MAC address for port %u", 
               portid);
        goto __finish;
    }

    dfw_log_write(LOG_INFO, "Port %u MAC: %02"PRIx8":%02"PRIx8":%02"PRIx8
           ":%02"PRIx8":%02"PRIx8":%02"PRIx8"\n",
            portid,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    /* 启用混杂模式以接收所有数据包 */
    tmp_ret = rte_eth_promiscuous_enable(portid);
    if (tmp_ret != 0) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_eth_promiscuous_enable() Error enabling promiscuous mode for port %u", 
               portid);
        goto __finish;
    }

    dfw_log_write(LOG_INFO, "dfw_dpdk_init() Port %u initialized successfully.", portid);


    ret = 0;
__finish:
    return ret;
}


static int dfw_check_all_ports_link_status(uint32_t port_mask) {

    #define CHECK_INTERVAL 100 /* 100ms */
    #define MAX_CHECK_TIME 90 /* 总共 9s (90 * 100ms) */

	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	int ret;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

	dfw_log_write(LOG_INFO, "Checking link status...");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			ret = rte_eth_link_get_nowait(portid, &link);
			if (ret < 0) {
				all_ports_up = 0;
				if (print_flag == 1)
					dfw_log_write(LOG_WARNING, "Port %u link get failed: %s",
						portid, rte_strerror(-ret));
				continue;
			}
			/* 打印链路状态 */
			if (print_flag == 1) {
				dfw_log_write(LOG_INFO, "Port %u Link Status: %s, Speed: %u Mbps, Duplex: %s\n",
                portid,
                link.link_status ? "UP" : "DOWN",
                link.link_speed,
                link.link_duplex ? "FULL" : "HALF");
				continue;
			}
			
			if (link.link_status == RTE_ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* 打印了所有端口的链路状态，跳出循环 */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* 如果所有链路都启动或者超时，设置打印标志 */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
		}
	}
    return all_ports_up;
}

int dfw_dpdk_init(int argc, char **argv) {

    int ret = -1;
    int parsed_argc = 0;
    dfwContext *dfw_ctx = NULL;
    uint16_t nb_ports;
    uint16_t portid = 0;
    unsigned int nb_mbufs = 0;
    unsigned int lcore_id = 0;
    unsigned int lcore_array[RTE_MAX_LCORE] = {0};
    int lcore_array_index = 0;
    int rx_port_queue_map_index = 0;
    int tx_port_queue_map_index = 0;
    dfw_log_init(LOG_DEBUG, NULL);
    parsed_argc = rte_eal_init(argc, argv);
    if(parsed_argc < 0) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_eal_init() error.");
        goto __finish;
    }
    argc -= parsed_argc;
    argv += parsed_argc;

    dfw_ctx = dfw_context_instance();
    if(!dfw_ctx) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() dfw_context_instance() error.");
        goto __finish;
    }
    

    /* TODO 自己的参数处理 */
    // ...

    /* 加载配置 */
    if(dwf_load_cfg() < 0) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() dwf_load_cfg() error.");
        goto __finish;
    }
    dfw_log_init(dfw_ctx->dfw_config.log_level, dfw_ctx->dfw_config.logfile_path);
    nb_ports = rte_eth_dev_count_avail();
    if(nb_ports == 0) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_eth_dev_count_avail() No Ethernet ports.");
        goto __finish;
    }

    if ((dfw_ctx->enable_eth_port_mask) & ~((1 << nb_ports) - 1)) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() Invalid portmask; possible (0x%x)",
			(1 << nb_ports) - 1);
        goto __finish;
    }

    dfw_ctx->eth_port_count = __builtin_popcount(dfw_ctx->enable_eth_port_mask);
    /* 规定可用端口必须大于等于 2 */
    if (dfw_ctx->eth_port_count < 2) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() error: The number of available ports must be at least 2.");
        goto __finish;
    }

    /* 获取所有可用的逻辑核心 */
    lcore_id = rte_get_next_lcore(-1, 1, 0);
    while (lcore_id < RTE_MAX_LCORE) {
        lcore_array[lcore_array_index++] = lcore_id;
        lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    }
    if(lcore_array_index == 0) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() error: No available lcore.");
        goto __finish;
    }
    
    if( (dfw_ctx->dfw_lcore_conf.rx_lcore_num + 
         dfw_ctx->dfw_lcore_conf.tx_lcore_num + 
         dfw_ctx->dfw_lcore_conf.process_lcore_num) > lcore_array_index ) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() error: Not enough lcores for rx, tx and process. "
                                 "Need at least %u lcores.", 
                                 dfw_ctx->dfw_lcore_conf.rx_lcore_num + 
                                 dfw_ctx->dfw_lcore_conf.tx_lcore_num + 
                                 dfw_ctx->dfw_lcore_conf.process_lcore_num);
        goto __finish;
    }

    /* 分配逻辑核心ID给RX、TX和处理核 */
    int lcore_used_index = 0;
    /* RX核 */
    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.rx_lcore_num; ++i) {
        dfw_ctx->dfw_lcore_conf.rx_lcore_ids[i] = lcore_array[lcore_used_index++];
    }
    /* TX核 */
    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.tx_lcore_num; ++i) {
        dfw_ctx->dfw_lcore_conf.tx_lcore_ids[i] = lcore_array[lcore_used_index++];
    }
    /* 处理核 */
    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.process_lcore_num; ++i) {
        dfw_ctx->dfw_lcore_conf.process_lcore_ids[i] = lcore_array[lcore_used_index++];
    }

    /* 检查端口队列数量是否超过最大限制 + 匹配端口 */
    RTE_ETH_FOREACH_DEV(portid) {
        if ((dfw_ctx->enable_eth_port_mask & (1 << portid)) == 0) 
            continue;

        struct rte_eth_dev_info dev_info;
        if(rte_eth_dev_info_get(portid, &dev_info) < 0) {
            dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_eth_dev_info_get() error: can not get eth dev info.");
            goto __finish;
        }
        if( dfw_ctx->eth_nb_rx_queue == 0 || dfw_ctx->eth_nb_tx_queue == 0 ||
            dfw_ctx->eth_nb_rx_queue > dev_info.max_rx_queues ||
            dfw_ctx->eth_nb_tx_queue > dev_info.max_tx_queues) {
            dfw_log_write(LOG_ERROR, "dfw_dpdk_init() error: need to [rx_queue_num > 0] && [tx_queue_num > 0] && "
                                     "[rx_queue_num <= eth dev max_rx_queue_num] && "
                                     "[tx_queue_num <= eth dev max_tx_queue_num].");
            goto __finish;
        }

        int flag = 0;
        const char *dev_name = rte_dev_name(dev_info.device);
        dfw_log_write(LOG_INFO, "dev_name: %s", dev_name);
        for(int i = 0; i < dfw_ctx->dfw_eth_port_conf.eth_port_entry_count; ++i) {

            if(dev_name != NULL && strcmp(dfw_ctx->dfw_eth_port_conf.eth_port_entry[i].eth_pci, dev_name) == 0) {
                struct rte_ether_addr addr;
                if(rte_eth_macaddr_get(portid, &addr) < 0) {
                    dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_eth_macaddr_get() error: can not get mac addr for portid[%u].",
                                   portid);
                    goto __finish;
                }
                memcpy(&dfw_ctx->dfw_eth_port_conf.eth_port_entry[i].eth_mac.addr_bytes,
                        &addr.addr_bytes, sizeof(addr.addr_bytes));
                dfw_ctx->dfw_eth_port_conf.eth_port_entry[i].port_id = portid;
                /* 放入 eth_port_mapping */
                dfw_ctx->dfw_eth_port_conf.eth_port_mapping[portid] = &dfw_ctx->dfw_eth_port_conf.eth_port_entry[i];
                flag = 1;
                break;
            }
        }
        if(!flag) {
            dfw_log_write(LOG_ERROR, "dfw_dpdk_init() error: can not find matched port config for portid[%u], pci[%s].",
                           portid, dev_name ? dev_name : "(null)");
            goto __finish;
        }
        
    }
    
    

    /* 初始化 Process Core IP Frag 表 */
    uint8_t process_lcore_num = dfw_ctx->dfw_lcore_conf.process_lcore_num;
    dfw_ctx->dfw_ipfrag_conf.frag_tables = 
            malloc(sizeof(struct rte_ip_frag_tbl *) * process_lcore_num);
    if(!dfw_ctx->dfw_ipfrag_conf.frag_tables) {
        dfw_log_write(LOG_ERROR, 
            "dfw_dpdk_init() malloc() error: allocate frag_tables pointers failed.");
        goto __finish;
    }
    memset(dfw_ctx->dfw_ipfrag_conf.frag_tables, 0, 
        sizeof(struct rte_ip_frag_tbl *) * process_lcore_num);

    dfw_ctx->dfw_ipfrag_conf.death_rows = 
            malloc(sizeof(struct rte_ip_frag_death_row) * process_lcore_num);
    if(!dfw_ctx->dfw_ipfrag_conf.death_rows) {
        dfw_log_write(LOG_ERROR, 
            "dfw_dpdk_init() malloc() error: allocate death_rows pointers failed.");
        goto __finish;
    }
    memset(dfw_ctx->dfw_ipfrag_conf.death_rows, 0, sizeof(struct rte_ip_frag_death_row) * process_lcore_num);
    uint64_t frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * IP_FRAG_TAL_MAX_FLOW_TTL;
    for(int i = 0; i < process_lcore_num; ++i) {
        dfw_ctx->dfw_ipfrag_conf.frag_tables[i] 
                = rte_ip_frag_table_create(
                        dfw_ctx->dfw_ipfrag_conf.buckut_num,
                        dfw_ctx->dfw_ipfrag_conf.bucket_entries,
                        dfw_ctx->dfw_ipfrag_conf.max_entries,
                        frag_cycles,
                        rte_lcore_to_socket_id(dfw_ctx->dfw_lcore_conf.process_lcore_ids[i])
                    );
        if(!dfw_ctx->dfw_ipfrag_conf.frag_tables[i]) {
            dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_ip_frag_table_create() error: create ip fragment table failed. "
                                     "process_lcore_idx[%u]", i);
            goto __finish;
        }
    }


    /* 初始化Process ring */
    dfw_ctx->dfw_ring_conf.process_rings = 
        (struct rte_ring**)malloc(sizeof(struct rte_ring*) * dfw_ctx->dfw_lcore_conf.process_lcore_num);
    if(!dfw_ctx->dfw_ring_conf.process_rings) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() malloc() error: allocate process ring pointers failed.");
        goto __finish;
    }
    memset(dfw_ctx->dfw_ring_conf.process_rings, 0, 
           sizeof(struct rte_ring*) * dfw_ctx->dfw_lcore_conf.process_lcore_num);
    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.process_lcore_num; ++i) {
        char ring_name[32] = {0};
        memset(ring_name, 0, sizeof(ring_name));
        snprintf(ring_name, sizeof(ring_name), "process_ring_%u", i);
        dfw_ctx->dfw_ring_conf.process_rings[i] = 
            rte_ring_create(
                ring_name,
                dfw_ctx->dfw_ring_conf.ring_elem_count,
                rte_socket_id(),
                0
            );
        if(!dfw_ctx->dfw_ring_conf.process_rings[i]) {
            dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_ring_create() error: create process ring failed. "
                                     "process_lcore_idx[%u]", i);
            goto __finish;
        }
    }


    /* 初始化TX ring */
    RTE_ETH_FOREACH_DEV(portid) {
        char ring_name[32] = {0};
        if ((dfw_ctx->enable_eth_port_mask & (1 << portid)) == 0) 
            continue;
        dfw_ctx->dfw_ring_conf.tx_queue_rings[portid] = 
            (struct rte_ring**)malloc(sizeof(struct rte_ring*) * dfw_ctx->eth_nb_tx_queue);
        memset(dfw_ctx->dfw_ring_conf.tx_queue_rings[portid], 0, 
               sizeof(struct rte_ring*) * dfw_ctx->eth_nb_tx_queue);
        if(!dfw_ctx->dfw_ring_conf.tx_queue_rings[portid]) {
            dfw_log_write(LOG_ERROR, "dfw_dpdk_init() malloc() error: allocate tx ring pointers failed. "
                                     "portid[%u]", portid);
            goto __finish;
        }
        for(int q = 0; q < dfw_ctx->eth_nb_tx_queue; ++q) {
            memset(ring_name, 0, sizeof(ring_name));
            snprintf(ring_name, sizeof(ring_name), "tx_ring_%u_%u", portid, q);
            dfw_ctx->dfw_ring_conf.tx_queue_rings[portid][q] = 
                rte_ring_create(
                    ring_name,
                    dfw_ctx->dfw_ring_conf.ring_elem_count,
                    rte_socket_id(),
                    0
                );
            if(!dfw_ctx->dfw_ring_conf.tx_queue_rings[portid][q]) {
                dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_ring_create() error: create tx ring failed. "
                                         "portid[%u], tx_queue[%u]", 
                                         portid, q);
                goto __finish;
            }
        }
    }

    /* 初始化 msg_from_proc_lcore*/
    dfw_ctx->dfw_ring_conf.msg_from_proc_lcore = 
        rte_ring_create("ring_msg_from_proc_lcore", 
                        dfw_ctx->dfw_ring_conf.ring_elem_count,
                        rte_socket_id(), 0);
    if(!dfw_ctx->dfw_ring_conf.msg_from_proc_lcore) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_ring_create() error: can not create msg_from_proc_locre ring.");
        goto __finish;
    }

    /* 绑定端口RX和TX队列到核 */
    RTE_ETH_FOREACH_DEV(portid) {
        /* 跳过未启用的端口 */
        if ((dfw_ctx->enable_eth_port_mask & (1 << portid)) == 0)
            continue;
        
        /* 绑定端口的RX队列到核 */
        for(int q = 0; q < dfw_ctx->eth_nb_rx_queue; ++q) {
            int choose_lcore_id_idx = 
                rx_port_queue_map_index % dfw_ctx->dfw_lcore_conf.rx_lcore_num;
            unsigned int choose_lcore_id = 
                dfw_ctx->dfw_lcore_conf.rx_lcore_ids[choose_lcore_id_idx];    
            int pq_map_idx = 
                dfw_ctx->rx_port_queue_mapping[choose_lcore_id].idx;
            if(pq_map_idx >= MAX_PORT_QUEUE_MAP_PRE_LCORE) {
                dfw_log_write(LOG_ERROR, "dfw_dpdk_init() error: Port-to-queue mapping out of range.");
                goto __finish;
            }
            dfw_ctx->rx_port_queue_mapping[choose_lcore_id]
                .pq_map[pq_map_idx].port_id = portid;
            dfw_ctx->rx_port_queue_mapping[choose_lcore_id]
                .pq_map[pq_map_idx].queue_id = q;
            dfw_log_write(LOG_INFO, "dfw_dpdk_init() lcore %u: port %u rx_queue %u",
                choose_lcore_id, portid, q);
            dfw_ctx->rx_port_queue_mapping[choose_lcore_id].idx++;
            rx_port_queue_map_index++;
            
        }   
        
        /* 绑定端口的TX队列到核 */
        for(int q = 0; q < dfw_ctx->eth_nb_tx_queue; ++q) {
            int choose_lcore_id_idx = 
                tx_port_queue_map_index % dfw_ctx->dfw_lcore_conf.tx_lcore_num;
            unsigned int choose_lcore_id = 
                dfw_ctx->dfw_lcore_conf.tx_lcore_ids[choose_lcore_id_idx];    
            int pq_map_idx = 
                dfw_ctx->tx_port_queue_mapping[choose_lcore_id].idx;
            if(pq_map_idx >= MAX_PORT_QUEUE_MAP_PRE_LCORE) {
                dfw_log_write(LOG_ERROR, "dfw_dpdk_init() error: Port-to-queue mapping out of range.");
                goto __finish;
            }
            dfw_ctx->tx_port_queue_mapping[choose_lcore_id]
                .pq_map[pq_map_idx].port_id = portid;
            dfw_ctx->tx_port_queue_mapping[choose_lcore_id]
                .pq_map[pq_map_idx].queue_id = q;
            dfw_log_write(LOG_INFO, "dfw_dpdk_init() lcore %u: port %u tx_queue %u",
                choose_lcore_id, portid, q);
            dfw_ctx->tx_port_queue_mapping[choose_lcore_id].idx++;
            tx_port_queue_map_index++;
        }
    }

    /* 创建内存池 */
    nb_mbufs = RTE_MAX(nb_ports * (dfw_ctx->eth_rx_desc_num + dfw_ctx->eth_tx_desc_num + MAX_PKT_BURST +
		lcore_array_index * MEMPOOL_CACHE_SIZE), 8192U);
    
    dfw_ctx->mempool = rte_pktmbuf_pool_create("mbuf_pool", nb_mbufs,
		MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());
    if(!dfw_ctx->mempool) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() rte_pktmbuf_pool_create() error.");
        goto __finish;
    } 

    /* 端口初始化 */
    portid = 0;
    RTE_ETH_FOREACH_DEV(portid) {
        if((dfw_ctx->enable_eth_port_mask & (1 << portid)) == 0)
            continue;
        if(dfw_port_init(portid) < 0) {
            dfw_log_write(LOG_ERROR, "dfw_dpdk_init() dfw_port_init() error.");
            goto __finish;
        }
    }

    if(!dfw_check_all_ports_link_status(dfw_ctx->enable_eth_port_mask)) {
        dfw_log_write(LOG_ERROR, "dfw_dpdk_init() dfw_check_all_ports_link_status() error: link state error.");
        goto __finish;
    }
    ret = 0;
__finish:
    if(ret < 0) {
        if(parsed_argc > 0) {
            portid = 0;
            RTE_ETH_FOREACH_DEV(portid) {
                if((dfw_ctx->enable_eth_port_mask & (1 << portid)) == 0)
                    continue;
                rte_eth_dev_stop(portid);
                rte_eth_dev_close(portid);
            }
            dfw_context_destory();
            rte_eal_cleanup();
        }
    }
    return ret;
}