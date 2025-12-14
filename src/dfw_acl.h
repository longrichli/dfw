#ifndef __DFW_ACL_H__
#define __DFW_ACL_H__
#include "dfw_pkg_proceesor.h"
#include <stdint.h>
#include <rte_ip.h>


#define DFW_ACL_MAX_RULES               (1024)

typedef enum _dfw_acl_action {
    DFW_ACL_PERMIT = 0,
    DFW_ACL_DENY   = 1,
} dfwAclAction;

typedef struct _dfw_acl_rule {
    uint32_t src_ip;
    uint32_t src_mask;

    uint32_t dst_ip;
    uint32_t dst_mask;

    uint16_t src_port_min;
    uint16_t src_port_max;

    uint16_t dst_port_min;
    uint16_t dst_port_max;

    uint8_t  proto;     // IPPROTO_TCP / UDP / 0 = ANY
    dfwAclAction action;
} dfwAclRule;


typedef struct _dfw_acl_table {
    uint32_t rule_count;
    dfwAclRule rules[DFW_ACL_MAX_RULES];
    dfwAclAction default_action;
} dfwAclTable;

dfwPkgProcessResult dfw_acl_process(struct rte_ipv4_hdr *ipv4_hdr);




#endif /* __DFW_ACL_H__ */