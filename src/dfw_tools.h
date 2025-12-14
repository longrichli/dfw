#ifndef __DFW_TOOLS_H__
#define __DFW_TOOLS_H__

#include <stdio.h>
#include <rte_cycles.h>

#define NET_NUMBER(ip, netmask) ((ip) & (netmask))


FILE *dfw_create_file(const char *filename, const char* mode);
uint64_t ms_to_tsc(uint64_t ms);
int dfw_parse_port_range(const char *port_str,
                     uint16_t *min_port,
                     uint16_t *max_port);


#endif /* __DFW_TOOLS_H__ */