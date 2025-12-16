#include "dfw_pkg_proceesor.h"
#include "dfw.h"
#include "dfw_arp.h"
#include "dfw_nat.h"
#include "dfw_route.h"
#include "dfw_flow.h"
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>

static inline int dfw_is_private_ipv4(uint32_t ip)
{
    ip = rte_be_to_cpu_32(ip);

    /* 10.0.0.0/8 */
    if ((ip & 0xFF000000) == 0x0A000000)
        return 1;

    /* 172.16.0.0/12 */
    if ((ip & 0xFFF00000) == 0xAC100000)
        return 1;

    /* 192.168.0.0/16 */
    if ((ip & 0xFFFF0000) == 0xC0A80000)
        return 1;

    /* 127.0.0.0/8 */
    if ((ip & 0xFF000000) == 0x7F000000)
        return 1;

    /* 169.254.0.0/16 */
    if ((ip & 0xFFFF0000) == 0xA9FE0000)
        return 1;

    return 0;
}

static inline void
dfw_dump_arp_hdr(const struct rte_arp_hdr *arp)
{
    if (arp == NULL) {
        dfw_log_write(LOG_ERROR,"ARP header: <NULL>");
        return;
    }

    uint16_t opcode = rte_be_to_cpu_16(arp->arp_opcode);

    dfw_log_write(LOG_INFO,"ARP Header:");

    dfw_log_write(LOG_INFO,"  hrd = %u", rte_be_to_cpu_16(arp->arp_hardware));
    if (rte_be_to_cpu_16(arp->arp_hardware) == RTE_ARP_HRD_ETHER)
        dfw_log_write(LOG_INFO," (Ethernet)");
    dfw_log_write(LOG_INFO,"\n");

    dfw_log_write(LOG_INFO,"  pro = 0x%04X", rte_be_to_cpu_16(arp->arp_protocol));
    if (rte_be_to_cpu_16(arp->arp_protocol) == RTE_ETHER_TYPE_IPV4)
        dfw_log_write(LOG_INFO," (IPv4)");
    dfw_log_write(LOG_INFO,"\n");
    dfw_log_write(LOG_INFO,"  opcode = %u", opcode);
    switch (opcode) {
    case RTE_ARP_OP_REQUEST:
        dfw_log_write(LOG_INFO," (REQUEST)");
        break;
    case RTE_ARP_OP_REPLY:
        dfw_log_write(LOG_INFO," (REPLY)");
        break;
    default:
        dfw_log_write(LOG_INFO," (UNKNOWN)");
        break;
    }
    dfw_log_write(LOG_INFO,"\n");

    dfw_log_write(LOG_INFO,"  sender_mac = %02X:%02X:%02X:%02X:%02X:%02X",
           arp->arp_data.arp_sha.addr_bytes[0],
           arp->arp_data.arp_sha.addr_bytes[1],
           arp->arp_data.arp_sha.addr_bytes[2],
           arp->arp_data.arp_sha.addr_bytes[3],
           arp->arp_data.arp_sha.addr_bytes[4],
           arp->arp_data.arp_sha.addr_bytes[5]);

    uint32_t sip = rte_be_to_cpu_32(arp->arp_data.arp_sip);
    dfw_log_write(LOG_INFO,"  sender_ip  = %u.%u.%u.%u",
           (sip >> 24) & 0xFF,
           (sip >> 16) & 0xFF,
           (sip >> 8) & 0xFF,
           sip & 0xFF);

    dfw_log_write(LOG_INFO,"  target_mac = %02X:%02X:%02X:%02X:%02X:%02X",
           arp->arp_data.arp_sha.addr_bytes[0],
           arp->arp_data.arp_tha.addr_bytes[1],
           arp->arp_data.arp_tha.addr_bytes[2],
           arp->arp_data.arp_tha.addr_bytes[3],
           arp->arp_data.arp_tha.addr_bytes[4],
           arp->arp_data.arp_tha.addr_bytes[5]);

    uint32_t tip = rte_be_to_cpu_32(arp->arp_data.arp_tip);
    dfw_log_write(LOG_INFO,"  target_ip  = %u.%u.%u.%u",
           (tip >> 24) & 0xFF,
           (tip >> 16) & 0xFF,
           (tip >> 8) & 0xFF,
           tip & 0xFF);
}

void static update_ip_tcp_udp_cksum(struct rte_ipv4_hdr *ipv4_hdr) {
    assert(ipv4_hdr);

    ipv4_hdr->hdr_checksum = 0;
    ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr *tcp_hdr = (struct rte_tcp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
        tcp_hdr->cksum = 0;
        tcp_hdr->cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, tcp_hdr);
    } else if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
        udp_hdr->dgram_cksum = 0;
        udp_hdr->dgram_cksum = rte_ipv4_udptcp_cksum(ipv4_hdr, udp_hdr);
    }
}

static dfwPkgProcessResult dfw_process_arp(struct rte_mbuf *mbuf) {
    assert(mbuf);
    
    struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_arp_hdr *arp_hdr = (struct rte_arp_hdr *)(ether_hdr + 1);
    //dfw_dump_arp_hdr(arp_hdr);
    int merge_flag = 0;
    if(arp_hdr->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER)) {
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    dfwArpEntry *arp_entry = NULL;
    uint32_t ip = arp_hdr->arp_data.arp_sip;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    if(rte_hash_lookup_data(dfw_ctx->dfw_arp_conf.arp_table, 
                         &ip, (void **)&arp_entry) >= 0) {
        dfw_update_arp_entry(ip, &arp_hdr->arp_data.arp_sha);
        merge_flag = 1;
    }
    uint16_t portid = 0;
    if(dfw_arp_is_request_my_ip(arp_hdr->arp_data.arp_tip, &portid)) {
        if(merge_flag == 0) {
            dfw_update_arp_entry(ip, &arp_hdr->arp_data.arp_sha);
        }
        if(arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
            dfw_arp_send_arp_reply(mbuf, portid);
        } else if(arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
            dfw_update_arp_entry(ip, &arp_hdr->arp_data.arp_sha);
            dfw_send_arp_pending_flash_msg(ip);
        }
    }
    return DFW_PKG_PROCESS_RESULT_DROP;
}

static dfwPkgProcessResult dfw_process_ipv4(struct rte_mbuf *mbuf,
                            struct rte_ip_frag_tbl *frag_table,
                            struct rte_ip_frag_death_row *death_row,
                            uint64_t tms,
                            uint16_t *out_portid) {
    assert(mbuf);
    struct rte_ether_hdr *ether_hdr = 
        rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
    struct rte_ipv4_hdr *ipv4_hdr = 
        rte_pktmbuf_mtod_offset(mbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    if(rte_ipv4_frag_pkt_is_fragmented(ipv4_hdr)) {
        struct rte_mbuf *mo = NULL;

        mbuf->l2_len = sizeof(struct rte_ether_hdr);
        mbuf->l3_len = (ipv4_hdr->version_ihl & 0x0F) << 2;
        mo = rte_ipv4_frag_reassemble_packet(frag_table, death_row, mbuf, tms, ipv4_hdr);
		if(mo == NULL) return DFW_PKG_PROCESS_RESULT_DROP;
        if (mo != mbuf) {
			mbuf = mo;
			ether_hdr = rte_pktmbuf_mtod(mbuf,
					struct rte_ether_hdr *);
			ipv4_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
		}
    }

    /* TODO 处理 IPv4 包 */
    dfwPkgProcessResult res;
    int src_ip_is_priv = 0;
    int dst_ip_is_priv = 0;
    int need_to_snat = 0, need_to_dnat = 0;
    if(dfw_ctx->dfw_nat_conf.enable_nat) {
        src_ip_is_priv = dfw_is_private_ipv4(ipv4_hdr->src_addr);
        dst_ip_is_priv = dfw_is_private_ipv4(ipv4_hdr->dst_addr);
        if(src_ip_is_priv && !dst_ip_is_priv) {
            need_to_snat = 1;
        } else if(!src_ip_is_priv) {
            need_to_dnat = 1;
        }
    }
    
    /* DNAT */
    if(dfw_ctx->dfw_nat_conf.enable_nat && need_to_dnat) {
        res = dfw_nat_dnat_process(ipv4_hdr);
        if(res != DFW_PKG_PROCESS_RESULT_FORWARD) {
            return res;
        }
    }

    /* ACL 匹配 */
    res = dfw_acl_process(ipv4_hdr);
    if(res != DFW_PKG_PROCESS_RESULT_FORWARD) {
        return res;
    }

    /* 路由 */
    struct rte_ether_addr src_mac, dst_mac;
    res = dfw_route_process(ipv4_hdr, out_portid, &src_mac, &dst_mac, mbuf);
    if(res != DFW_PKG_PROCESS_RESULT_FORWARD) {
        return (dfwPkgProcessResult)res;
    }

    /* SNAT */
    if(dfw_ctx->dfw_nat_conf.enable_nat && need_to_snat) {
        res = dfw_nat_snat_process(ipv4_hdr, *out_portid);
        if(res != DFW_PKG_PROCESS_RESULT_FORWARD) {
            return res;
        }
    }
    
    /* 修改以太网头部 */
    rte_memcpy(&ether_hdr->dst_addr.addr_bytes, dst_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
    rte_memcpy(&ether_hdr->src_addr.addr_bytes, src_mac.addr_bytes, RTE_ETHER_ADDR_LEN);
    
    
    /* 更新校验和 */
    update_ip_tcp_udp_cksum(ipv4_hdr);
    
    return DFW_PKG_PROCESS_RESULT_FORWARD;
}

static inline void
dfw_dump_ether_hdr(const struct rte_ether_hdr *eth)
{
    if (eth == NULL) {
        dfw_log_write(LOG_INFO,"Ethernet header: <NULL>\n");
        return;
    }

    dfw_log_write(LOG_INFO,"Ethernet Header:\n");

    dfw_log_write(LOG_INFO,"  dst_mac = %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->dst_addr.addr_bytes[0],
           eth->dst_addr.addr_bytes[1],
           eth->dst_addr.addr_bytes[2],
           eth->dst_addr.addr_bytes[3],
           eth->dst_addr.addr_bytes[4],
           eth->dst_addr.addr_bytes[5]);

    dfw_log_write(LOG_INFO,"  src_mac = %02X:%02X:%02X:%02X:%02X:%02X\n",
           eth->src_addr.addr_bytes[0],
           eth->src_addr.addr_bytes[1],
           eth->src_addr.addr_bytes[2],
           eth->src_addr.addr_bytes[3],
           eth->src_addr.addr_bytes[4],
           eth->src_addr.addr_bytes[5]);

    uint16_t ether_type = rte_be_to_cpu_16(eth->ether_type);

    dfw_log_write(LOG_INFO,"  ether_type = 0x%04X", ether_type);

    switch (ether_type) {
    case RTE_ETHER_TYPE_IPV4:
        dfw_log_write(LOG_INFO," (IPv4)");
        break;
    case RTE_ETHER_TYPE_IPV6:
        dfw_log_write(LOG_INFO," (IPv6)");
        break;
    case RTE_ETHER_TYPE_ARP:
        dfw_log_write(LOG_INFO," (ARP)");
        break;
    case RTE_ETHER_TYPE_VLAN:
        dfw_log_write(LOG_INFO," (802.1Q VLAN)");
        break;
    default:
        dfw_log_write(LOG_INFO," (Unknown)");
        break;
    }

    dfw_log_write(LOG_INFO,"\n");
}

static dfwPkgProcessResult dfw_pkg_process(struct rte_mbuf *mbuf, 
                    struct rte_ip_frag_tbl *frag_table,
                    struct rte_ip_frag_death_row *death_row,
                    uint64_t tms,
                    uint16_t *out_portid,
                    struct rte_ring *process_ring
                ) {
    assert(mbuf);
    /* TODO 包处理逻辑 */

    struct rte_ether_hdr *ether_hdr = rte_pktmbuf_mtod(mbuf, 
            struct rte_ether_hdr *);
    dfw_dump_ether_hdr(ether_hdr);
    if(ether_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        return dfw_process_arp(mbuf);
    } else if(ether_hdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
        return dfw_process_ipv4(mbuf, frag_table, death_row, tms, out_portid);
    } else {
        return DFW_PKG_PROCESS_RESULT_DROP;
    }
    
    return DFW_PKG_PROCESS_RESULT_DROP;
}

int dfw_pkg_process_loop(void *arg) {
    unsigned lcore_id = rte_lcore_id();
    struct rte_mbuf *pkt_burst[MAX_PKT_BURST];
    struct rte_ring *process_ring = NULL;
    struct rte_ip_frag_tbl *frag_table = NULL;
    struct rte_ip_frag_death_row *death_row = NULL;
    uint64_t cur_tsc;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfw_log_write(LOG_INFO, "dfw_pkg_process_loop() started on lcore %u", lcore_id);
    assert(dfw_ctx->dfw_ring_conf.process_rings);


    for(int i = 0; i < dfw_ctx->dfw_lcore_conf.process_lcore_num; ++i) {
        if(dfw_ctx->dfw_lcore_conf.process_lcore_ids[i] == lcore_id) {
            process_ring = dfw_ctx->dfw_ring_conf.process_rings[i];
            frag_table = dfw_ctx->dfw_ipfrag_conf.frag_tables[i];
            death_row = dfw_ctx->dfw_ipfrag_conf.death_rows + i;
            break;
        }
    }
    assert(process_ring);
    assert(frag_table);
    assert(death_row);
    while(dfw_ctx->is_loop) {
        uint16_t nb_pkt = 0;
        cur_tsc = rte_rdtsc();

        nb_pkt = rte_ring_dequeue_burst(process_ring, (void **)pkt_burst, MAX_PKT_BURST, NULL);
        if(unlikely(nb_pkt == 0)) {
            rte_pause();
            continue;
        }
        for(int k = 0; k < nb_pkt; ++k) {
            uint16_t portid = 0;
            dfwPkgProcessResult res;
            if (likely(k + PREFETCH_OFFSET < nb_pkt)) {
                rte_prefetch0(rte_pktmbuf_mtod(pkt_burst[k + PREFETCH_OFFSET], void *));
            }
            res = dfw_pkg_process(pkt_burst[k], frag_table, death_row, cur_tsc, &portid, process_ring);
            if(res == DFW_PKG_PROCESS_RESULT_DROP) {
                rte_pktmbuf_free(pkt_burst[k]);
            } else if(res == DFW_PKG_PROCESS_RESULT_DO_NOT_FORWARD) {
                // Do nothing
            } else if(res == DFW_PKG_PROCESS_RESULT_FORWARD) {
                uint32_t flow_hash = dfw_flow_key_hash_from_mbuf(pkt_burst[k]);
                uint16_t queue_id = flow_hash % dfw_ctx->eth_nb_tx_queue;
                struct rte_ring *tx_ring = 
                    dfw_ctx->dfw_ring_conf.tx_queue_rings[portid][queue_id];
                if(rte_ring_enqueue(tx_ring, (void *)pkt_burst[k]) < 0) {
                    rte_pktmbuf_free(pkt_burst[k]);
                }
            }

        }

        rte_ip_frag_free_death_row(death_row, PREFETCH_OFFSET);
    }
    return 0;
}