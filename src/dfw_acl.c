#include "dfw_acl.h"
#include "dfw.h"
#include "dfw_tools.h"
#include <rte_tcp.h>
#include <rte_udp.h>
#include <stdatomic.h>

dfwPkgProcessResult dfw_acl_process(struct rte_ipv4_hdr *ipv4_hdr) {
    assert(ipv4_hdr);
    
    struct rte_tcp_hdr *tcp_hdr = NULL;
    struct rte_udp_hdr *udp_hdr = NULL;
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);
    dfwAclTable *acl = (dfwAclTable *)atomic_load_explicit(&dfw_ctx->dfw_acl_conf.active_acl, memory_order_acquire);
    src_ip = ipv4_hdr->src_addr;
    dst_ip = ipv4_hdr->dst_addr;
    proto = ipv4_hdr->next_proto_id;
    
    if(ipv4_hdr->next_proto_id == IPPROTO_TCP) {
        tcp_hdr = (struct rte_tcp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
        src_port = tcp_hdr->src_port;
        dst_port = tcp_hdr->dst_port;
        
    } else if(ipv4_hdr->next_proto_id == IPPROTO_UDP) {
        udp_hdr = (struct rte_udp_hdr *)
                ((char *)ipv4_hdr + ((ipv4_hdr->version_ihl & 0x0F) << 2));
        src_port = udp_hdr->src_port;
        dst_port = udp_hdr->dst_port;
    }

    for(int i = 0; i < acl->rule_count; i++) {
        
        dfwAclRule *acl_rule = &acl->rules[i];

        /* 检查协议是否匹配，不匹配匹配下一个 */
        if (acl_rule->proto != 0 && proto != acl_rule->proto) {
            continue;
        }


        /* 检查源IP网络号是否匹配，不匹配匹配下一个 */
        if(NET_NUMBER(acl_rule->src_ip, acl_rule->src_mask) != 
           NET_NUMBER(src_ip, acl_rule->src_mask)) {
            continue;
        }

        /* 检查目的IP网络号是否匹配， 不匹配匹配下一个 */
        if(NET_NUMBER(acl_rule->dst_ip, acl_rule->dst_mask) != 
           NET_NUMBER(dst_ip, acl_rule->dst_mask)) {
            continue;
        }

        if(proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
            /* 检查源端口是否匹配， 不匹配匹配下一个 */
            if(src_port < acl_rule->src_port_min || src_port > acl_rule->src_port_max) {
                continue;
            }

            /* 检查目的端口是否匹配， 不匹配匹配下一个 */
            if(dst_port < acl_rule->dst_port_min || dst_port > acl_rule->dst_port_max) {
                continue;
            }
        }


        /* 匹配规则，执行动作 */
        if(acl_rule->action == DFW_ACL_DENY) {
            return DFW_PKG_PROCESS_RESULT_DROP;
        } else if(acl_rule->action == DFW_ACL_PERMIT) {
            return DFW_PKG_PROCESS_RESULT_FORWARD;
        }

    }

    /* 所有规则均不匹配， 执行默认动作 */
    if(acl->default_action == DFW_ACL_DENY) {
        return DFW_PKG_PROCESS_RESULT_DROP;
    } else if(acl->default_action == DFW_ACL_PERMIT) {
        return DFW_PKG_PROCESS_RESULT_FORWARD;
    }
    return DFW_PKG_PROCESS_RESULT_DROP;
}