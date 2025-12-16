#include "dfw_cfg.h"
#include "dfw.h"
#include "dfw_cjson.h"
#include "dfw_tools.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdatomic.h>


static int load_route_cfg(void)
{
    int ret = -1;

    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    const char *path = dfw_ctx->dfw_config.routefile_path;

    FILE *fp = fopen(path, "r");
    if (!fp) {
        dfw_log_write(LOG_ERROR, "load_route_cfg: cannot open file %s", path);
        goto __finish;
    }

    /* 读取 JSON 字符串 */
    fseek(fp, 0, SEEK_END);
    long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *json_buf = malloc(len + 1);
    if (!json_buf) {
        dfw_log_write(LOG_ERROR, "load_route_cfg: memory allocation failed");
        goto __finish;
    }

    fread(json_buf, 1, len, fp);
    json_buf[len] = '\0';

    /* 解析 JSON */
    cJSON *root = cJSON_Parse(json_buf);
    if (!root) {
        dfw_log_write(LOG_ERROR, "load_route_cfg: JSON format error");
        goto __finish;
    }

    cJSON *routes = cJSON_GetObjectItem(root, "routes");
    if (!routes || !cJSON_IsArray(routes)) {
        dfw_log_write(LOG_ERROR, "load_route_cfg: routes array not found");
        goto __finish;
    }

    dfw_ctx->dfw_route_conf.route_entry_count = 0;

    int count = cJSON_GetArraySize(routes);
    if (count > DFW_MAX_ROUTE_ENTRY)
        count = DFW_MAX_ROUTE_ENTRY;

    for (int i = 0; i < count; i++) {

        cJSON *item = cJSON_GetArrayItem(routes, i);
        if (!item) {
            dfw_log_write(LOG_ERROR, "load_route_cfg: invalid route entry");
            continue;
        };

        dfwRouteEntry *entry = 
           &dfw_ctx->dfw_route_conf.route_entries[i];
        memset(entry, 0, sizeof(dfwRouteEntry));

        /* destination */
        cJSON *destination = cJSON_GetObjectItem(item, "destination");
        if (destination && cJSON_IsString(destination)) {
            if(inet_pton(AF_INET, destination->valuestring, &entry->destination) < 0) {
                dfw_log_write(LOG_ERROR, "Invalid destination address: %s", destination->valuestring);
                goto __finish;
            }

        } else {
            dfw_log_write(LOG_ERROR, "Destination not found or invalid");
            goto __finish;
        }

        /* netmask */
        cJSON *netmask = cJSON_GetObjectItem(item, "netmask");
        if (netmask && cJSON_IsString(netmask)) {
            if(inet_pton(AF_INET, netmask->valuestring, &entry->netmask) < 0) {
                dfw_log_write(LOG_ERROR, "Invalid netmask address: %s", netmask->valuestring);
                goto __finish;
            }

        } else {
            dfw_log_write(LOG_ERROR, "Netmask not found or invalid");
            goto __finish;
        }

        /* gateway */
        cJSON *gateway = cJSON_GetObjectItem(item, "gateway");
        if (gateway && cJSON_IsString(gateway)) {
            if(inet_pton(AF_INET, gateway->valuestring, &entry->gateway) < 0) {
                dfw_log_write(LOG_ERROR, "Invalid gateway address: %s", gateway->valuestring);
                goto __finish;
            }

        } else {
            dfw_log_write(LOG_ERROR, "Gateway not found or invalid");
            goto __finish;
        }

        /* out_port */
        cJSON *out_port = cJSON_GetObjectItem(item, "out_port");
        if (out_port && cJSON_IsString(out_port)) {
            strncpy(entry->out_port, out_port->valuestring,
                    sizeof(entry->out_port)-1);
            entry->out_port[sizeof(entry->out_port)-1] = '\0';
        } else {
            dfw_log_write(LOG_ERROR, "Out_port not found or invalid");
            entry->out_port[0] = '\0';
        }

        /* metric */
        cJSON *metric = cJSON_GetObjectItem(item, "metric");
        if(metric && cJSON_IsNumber(metric)) {
            entry->metric = metric->valueint;
        } else {
            dfw_log_write(LOG_WARNING, "Metric not found or invalid, set to default 1");
            entry->metric = 1; // default metric
        }

        dfw_ctx->dfw_route_conf.route_entry_count++;
    }
    ret = 0;
__finish:
    if(root)
        cJSON_Delete(root);
    if(json_buf)
        free(json_buf);
    if(fp)
        fclose(fp);

    return ret;
}

static int load_acl_cfg(void)
{
    int ret = -1;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    FILE *fp = fopen(dfw_ctx->dfw_config.aclfile_path, "r");
    if (!fp) {
        dfw_log_write(LOG_ERROR, "load_acl_cfg: Failed to open acl config file: %s",
                      dfw_ctx->dfw_config.aclfile_path);
        goto __finish;
    }

    /* 读取文件内容 */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = malloc(fsize + 1);
    if (!buf) {
        dfw_log_write(LOG_ERROR, "load_acl_cfg: No memory for acl config");
        goto __finish;
    }
    memset(buf, 0, fsize + 1);
    fread(buf, 1, fsize, fp);
    buf[fsize] = 0;

    /* 解析 JSON */
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        dfw_log_write(LOG_ERROR, "load_acl_cfg: ACL JSON parse error: %s",
                      cJSON_GetErrorPtr());
        goto __finish;
    }

    /* 选择 inactive ACL table */
    dfwAclTable *old =
        (dfwAclTable *)atomic_load(&dfw_ctx->dfw_acl_conf.active_acl);
    dfwAclTable *table =
        (old == &dfw_ctx->dfw_acl_conf.acl_tables[0]) ?
        &dfw_ctx->dfw_acl_conf.acl_tables[1] :
        &dfw_ctx->dfw_acl_conf.acl_tables[0];

    memset(table, 0, sizeof(*table));

    /* default_action */
    cJSON *jdef = cJSON_GetObjectItem(root, "default_action");
    if (!jdef || !cJSON_IsString(jdef)) {
        dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid or missing default_action");
        goto __finish;
    }

    if (strcmp(jdef->valuestring, "permit") == 0) {
        table->default_action = DFW_ACL_PERMIT;
    } else if (strcmp(jdef->valuestring, "deny") == 0) {
        table->default_action = DFW_ACL_DENY;
    } else {
        dfw_log_write(LOG_ERROR, "load_acl_cfg: Unknown default_action: %s",
                      jdef->valuestring);
        goto __finish;
    }

    /* rules */
    cJSON *rules = cJSON_GetObjectItem(root, "rules");
    if (!rules || !cJSON_IsArray(rules)) {
        dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid ACL config: 'rules' not array");
        goto __finish;
    }

    int cnt = cJSON_GetArraySize(rules);

    for (int i = 0; i < cnt; ++i) {
        if (table->rule_count >= DFW_ACL_MAX_RULES) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: ACL rule overflow");
            goto __finish;
        }

        cJSON *r = cJSON_GetArrayItem(rules, i);
        if (!cJSON_IsObject(r)) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid ACL rule entry");
            goto __finish;
        }

        dfwAclRule *rule = &table->rules[table->rule_count];
        memset(rule, 0, sizeof(*rule));

        /* src_ip */
        cJSON *jsrc_ip = cJSON_GetObjectItem(r, "src_ip");
        cJSON *jsrc_mask = cJSON_GetObjectItem(r, "src_mask");
        if (!jsrc_ip || !jsrc_mask ||
            !cJSON_IsString(jsrc_ip) || !cJSON_IsString(jsrc_mask)) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid src_ip/src_mask");
            goto __finish;
        }
        if (inet_pton(AF_INET, jsrc_ip->valuestring, &rule->src_ip) < 0 ||
            inet_pton(AF_INET, jsrc_mask->valuestring, &rule->src_mask) < 0) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid src_ip/src_mask value");
            goto __finish;
        }

        /* dst_ip */
        cJSON *jdst_ip = cJSON_GetObjectItem(r, "dst_ip");
        cJSON *jdst_mask = cJSON_GetObjectItem(r, "dst_mask");
        if (!jdst_ip || !jdst_mask ||
            !cJSON_IsString(jdst_ip) || !cJSON_IsString(jdst_mask)) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid dst_ip/dst_mask");
            goto __finish;
        }
        if (inet_pton(AF_INET, jdst_ip->valuestring, &rule->dst_ip) < 0 ||
            inet_pton(AF_INET, jdst_mask->valuestring, &rule->dst_mask) < 0) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid dst_ip/dst_mask value");
            goto __finish;
        }

        /* proto */
        cJSON *jproto = cJSON_GetObjectItem(r, "proto");
        if (!jproto || !cJSON_IsString(jproto)) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid proto");
            goto __finish;
        }
        if (strcmp(jproto->valuestring, "tcp") == 0) {
            rule->proto = IPPROTO_TCP;
        } else if (strcmp(jproto->valuestring, "udp") == 0) {
            rule->proto = IPPROTO_UDP;
        } else if (strcmp(jproto->valuestring, "any") == 0) {
            rule->proto = 0;
        } else {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Unknown proto: %s",
                          jproto->valuestring);
            goto __finish;
        }

        /* ports default: any */
        rule->src_port_min = 0;
        rule->src_port_max = rte_cpu_to_be_16(65535);
        rule->dst_port_min = 0;
        rule->dst_port_max = rte_cpu_to_be_16(65535);

        cJSON *jsrc_port = cJSON_GetObjectItem(r, "src_port");
        if (jsrc_port && cJSON_IsString(jsrc_port)) {
            if(dfw_parse_port_range(jsrc_port->valuestring,
                             &rule->src_port_min,
                             &rule->src_port_max) < 0) {
                dfw_log_write(LOG_ERROR, "load_acl_cfg: parse src port range error: %s",
                          jsrc_port->valuestring);
                goto __finish;
            }
        }

        cJSON *jdst_port = cJSON_GetObjectItem(r, "dst_port");
        if (jdst_port && cJSON_IsString(jdst_port)) {
            if(dfw_parse_port_range(jdst_port->valuestring,
                             &rule->dst_port_min,
                             &rule->dst_port_max) < 0) {
                dfw_log_write(LOG_ERROR, "load_acl_cfg: parse dst port range error: %s",
                          jsrc_port->valuestring);
                goto __finish;
            }
        }

        /* action */
        cJSON *jact = cJSON_GetObjectItem(r, "action");
        if (!jact || !cJSON_IsString(jact)) {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Invalid action");
            goto __finish;
        }
        if (strcmp(jact->valuestring, "permit") == 0) {
            rule->action = DFW_ACL_PERMIT;
        } else if (strcmp(jact->valuestring, "deny") == 0) {
            rule->action = DFW_ACL_DENY;
        } else {
            dfw_log_write(LOG_ERROR, "load_acl_cfg: Unknown action: %s",
                          jact->valuestring);
            goto __finish;
        }

        table->rule_count++;
    }

    /* 原子切换 ACL 表 */
    atomic_store(&dfw_ctx->dfw_acl_conf.active_acl, (_Atomic dfwAclTable *)table);

    ret = 0;

__finish:
    if (fp)
        fclose(fp);
    if (buf)
        free(buf);
    if (root)
        cJSON_Delete(root);
    return ret;
}



static int load_eth_cfg(void) {
    int ret = -1;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    FILE *fp = fopen(dfw_ctx->dfw_config.ethfile_path, "r");
    if (!fp) {
        dfw_log_write(LOG_ERROR, "Failed to open eth config file: %s",
                      dfw_ctx->dfw_config.ethfile_path);
        goto __finish;
    }
    /* 读取文件内容 */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = malloc(fsize + 1);
    if (!buf) {
        goto __finish;
    }
    memset(buf, 0, fsize + 1);
    fread(buf, 1, fsize, fp);
    buf[fsize] = 0;

    /* 解析 JSON */
    cJSON *root = cJSON_Parse(buf);

    if (!root) {
        dfw_log_write(LOG_ERROR, "JSON parse error: %s",
                      cJSON_GetErrorPtr());
        goto __finish;
    }

    cJSON *ports = cJSON_GetObjectItem(root, "ports");
    if (!cJSON_IsArray(ports)) {
        dfw_log_write(LOG_ERROR, "Invalid config: 'ports' not array");
        goto __finish;
    }

    dfw_ctx->dfw_eth_port_conf.eth_port_entry_count = 0;

    int cnt = cJSON_GetArraySize(ports);

    for (int i = 0; i < cnt; ++i) {
        cJSON *p = cJSON_GetArrayItem(ports, i);
        if (!cJSON_IsObject(p)) {
            dfw_log_write(LOG_ERROR, "Invalid port entry.");
            goto __finish;
        }

        dfwEthPortEntry *entry =
            &dfw_ctx->dfw_eth_port_conf.eth_port_entry[
                dfw_ctx->dfw_eth_port_conf.eth_port_entry_count
            ];
        memset(entry, 0, sizeof(dfwEthPortEntry));
        /* name */
        cJSON *jname = cJSON_GetObjectItem(p, "name");
        if (jname && cJSON_IsString(jname)) {
            strncpy(entry->eth_name, jname->valuestring, sizeof(entry->eth_name));
        } else {
            dfw_log_write(LOG_ERROR, "Invalid port name.");
            goto __finish;
        }

        /* PCI */
        cJSON *jpci = cJSON_GetObjectItem(p, "pci");
        if(jpci && cJSON_IsString(jpci)) {
            strncpy(entry->eth_pci, jpci->valuestring, sizeof(entry->eth_pci));
        } else {
            dfw_log_write(LOG_ERROR, "Invalid PCI.");
            goto __finish;
        }

        /* type */
        cJSON *jtype = cJSON_GetObjectItem(p, "type");
        if (!jtype || !cJSON_IsString(jtype)) {
            dfw_log_write(LOG_ERROR, "Invalid port type.");
            goto __finish;
        }

        if (strcmp(jtype->valuestring, "wan") == 0) {
            entry->eth_port_type = DFW_ETH_PORT_TYPE_WAN;

        } else if (strcmp(jtype->valuestring, "wan_backup") == 0) {
            entry->eth_port_type = DFW_ETH_PORT_TYPE_WAN_BACKUP;

        } else if (strcmp(jtype->valuestring, "lan") == 0) {
            entry->eth_port_type = DFW_ETH_PORT_TYPE_LAN;

        } else if (strcmp(jtype->valuestring, "dmz") == 0) {
            entry->eth_port_type = DFW_ETH_PORT_TYPE_DMZ;

        } else {
            dfw_log_write(LOG_ERROR, "Unknown type: %s", jtype->valuestring);
            goto __finish;
        }

        /* IP */
        cJSON *jip = cJSON_GetObjectItem(p, "ip");
        if (!jip || !cJSON_IsString(jip)) {
            dfw_log_write(LOG_ERROR, "Invalid IP address.");
            goto __finish;
        }
        if(inet_pton(AF_INET, jip->valuestring, &entry->ip) < 0) {
            dfw_log_write(LOG_ERROR, "Invalid IP address: %s", jip->valuestring);
            goto __finish;
        }

        /* netmask */
        cJSON *jmask = cJSON_GetObjectItem(p, "netmask");
        if (!jmask || !cJSON_IsString(jmask)) {
            dfw_log_write(LOG_ERROR, "Invalid netmask address.");
            goto __finish;
        }
        if(inet_pton(AF_INET, jmask->valuestring, &entry->ipmask) < 0) {
            dfw_log_write(LOG_ERROR, "Invalid netmask address: %s", jmask->valuestring);
            goto __finish;
        }

        /* gateway */
        cJSON *jgw = cJSON_GetObjectItem(p, "gw");
        if (!jgw || !cJSON_IsString(jgw)) {
            dfw_log_write(LOG_ERROR, "Invalid gateway address.");
            goto __finish;
        }
        if(inet_pton(AF_INET, jgw->valuestring, &entry->gateway) < 0) {
            dfw_log_write(LOG_ERROR, "Invalid gateway address: %s", jgw->valuestring);
            goto __finish;
        }

        dfw_ctx->dfw_eth_port_conf.eth_port_entry_count++;
    }
    ret = 0;
__finish:
    if(fp)
        fclose(fp);
    if(buf)
        free(buf);
    if(root)
        cJSON_Delete(root);
    return ret;
}


static int load_common_cfg(void)
{
    int ret = -1;
    dfwContext *dfw_ctx = dfw_context_instance();
    assert(dfw_ctx);

    FILE *fp = fopen(dfw_ctx->dfw_config.cfgfile_path, "r");
    if (!fp) {
        dfw_log_write(LOG_ERROR, "load_common_cfg: Failed to open common config file: %s",
                      dfw_ctx->dfw_config.cfgfile_path);
        goto __finish;
    }

    /* 读取文件内容 */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = malloc(fsize + 1);
    if (!buf) {
        dfw_log_write(LOG_ERROR, "load_common_cfg: No memory for common cfg");
        goto __finish;
    }
    memset(buf, 0, fsize + 1);
    fread(buf, 1, fsize, fp);
    buf[fsize] = 0;

    /* 解析 JSON */
    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        dfw_log_write(LOG_ERROR, "load_common_cfg: JSON parse error: %s",
                      cJSON_GetErrorPtr());
        goto __finish;
    }

    /* ---------- 基础 ETH 参数 ---------- */
    cJSON *jrxq = cJSON_GetObjectItem(root, "eth_nb_rx_queue");
    cJSON *jtxq = cJSON_GetObjectItem(root, "eth_nb_tx_queue");
    cJSON *jmask = cJSON_GetObjectItem(root, "enable_eth_port_mask");

    if (!cJSON_IsNumber(jrxq) || !cJSON_IsNumber(jtxq) || !cJSON_IsNumber(jmask)) {
        dfw_log_write(LOG_ERROR, "load_common_cfg: Invalid eth global config");
        goto __finish;
    }

    dfw_ctx->eth_nb_rx_queue = jrxq->valueint;
    dfw_ctx->eth_nb_tx_queue = jtxq->valueint;
    dfw_ctx->enable_eth_port_mask = jmask->valueint;

    /* ---------- NAT ---------- */
    cJSON *jnat = cJSON_GetObjectItem(root, "dfw_nat_conf");
    if (jnat && cJSON_IsObject(jnat)) {

        cJSON *jen = cJSON_GetObjectItem(jnat, "enable_nat");
        cJSON *javail = cJSON_GetObjectItem(jnat, "nat_entry_avail_time_s");
        cJSON *jscan = cJSON_GetObjectItem(jnat, "nat_scan_time_ms");
        cJSON *jdead = cJSON_GetObjectItem(jnat, "nat_entry_dead_free_time_ms");

        if (!cJSON_IsNumber(jen) ||
            !cJSON_IsNumber(javail) ||
            !cJSON_IsNumber(jscan) ||
            !cJSON_IsNumber(jdead)) {
            dfw_log_write(LOG_ERROR, "load_common_cfg: Invalid NAT config");
            goto __finish;
        }

        dfw_ctx->dfw_nat_conf.enable_nat = jen->valueint;
        dfw_ctx->dfw_nat_conf.nat_entry_avail_time_s = javail->valueint;
        dfw_ctx->dfw_nat_conf.nat_scan_time_ms = jscan->valueint;
        dfw_ctx->dfw_nat_conf.nat_entry_dead_free_time_ms = jdead->valueint;
    }

    /* ---------- ARP ---------- */
    cJSON *jarp = cJSON_GetObjectItem(root, "dfw_arp_conf");
    if (jarp && cJSON_IsObject(jarp)) {

        #define GET_NUM(item, name)                     \
            cJSON *item = cJSON_GetObjectItem(jarp, name); \
            if (!cJSON_IsNumber(item)) {               \
                dfw_log_write(LOG_ERROR, "load_common_cfg: Invalid ARP config: %s", name); \
                goto __finish;                          \
            }

        GET_NUM(jdead,   "arp_entry_dead_free_time_ms");
        GET_NUM(jexp,    "arp_entry_expire_ms");
        GET_NUM(jretry,  "arp_entry_max_retry");
        GET_NUM(jpend,   "arp_entry_max_pending");
        GET_NUM(jintv,   "arp_retry_interval_ms");
        GET_NUM(jscan,   "arp_scan_time_ms");

        dfw_ctx->dfw_arp_conf.arp_entry_dead_free_time_ms = jdead->valueint;
        dfw_ctx->dfw_arp_conf.arp_entry_expire_ms = jexp->valueint;
        dfw_ctx->dfw_arp_conf.arp_entry_max_retry = jretry->valueint;
        dfw_ctx->dfw_arp_conf.arp_entry_max_pending = jpend->valueint;
        dfw_ctx->dfw_arp_conf.arp_retry_interval_ms = jintv->valueint;
        dfw_ctx->dfw_arp_conf.arp_scan_time_ms = jscan->valueint;

        #undef GET_NUM
    }

    /* ---------- 日志 & 文件路径 ---------- */
    cJSON *jcfg = cJSON_GetObjectItem(root, "dfw_config");
    if (jcfg && cJSON_IsObject(jcfg)) {

        #define GET_STR(dst, name)                                      \
            do {                                                        \
                cJSON *j = cJSON_GetObjectItem(jcfg, name);             \
                if (!cJSON_IsString(j)) {                               \
                    dfw_log_write(LOG_ERROR, "Invalid config: %s", name); \
                    goto __finish;                                      \
                }                                                       \
                strncpy(dst, j->valuestring, sizeof(dst));              \
            } while (0)

        GET_STR(dfw_ctx->dfw_config.logfile_path, "logfile_path");
        GET_STR(dfw_ctx->dfw_config.cfgfile_path, "cfgfile_path");
        GET_STR(dfw_ctx->dfw_config.ethfile_path, "ethfile_path");
        GET_STR(dfw_ctx->dfw_config.routefile_path, "routefile_path");
        GET_STR(dfw_ctx->dfw_config.aclfile_path, "aclfile_path");

        cJSON *jlevel = cJSON_GetObjectItem(jcfg, "log_level");
        if (!cJSON_IsString(jlevel)) {
            dfw_log_write(LOG_ERROR, "Invalid log_level");
            goto __finish;
        }

        if (strcmp(jlevel->valuestring, "DEBUG") == 0)
            dfw_ctx->dfw_config.log_level = LOG_DEBUG;
        else if (strcmp(jlevel->valuestring, "INFO") == 0)
            dfw_ctx->dfw_config.log_level = LOG_INFO;
        else if (strcmp(jlevel->valuestring, "ERROR") == 0)
            dfw_ctx->dfw_config.log_level = LOG_ERROR;
        else if (strcmp(jlevel->valuestring, "WARNING") == 0)
            dfw_ctx->dfw_config.log_level = LOG_WARNING;
        else {
            dfw_log_write(LOG_ERROR, "load_common_cfg: Unknown log level: %s",
                          jlevel->valuestring);
            goto __finish;
        }

        #undef GET_STR
    }

    /* ---------- lcore ---------- */
    cJSON *jlcore = cJSON_GetObjectItem(root, "dfw_lcore_conf");
    if (jlcore && cJSON_IsObject(jlcore)) {

        cJSON *jrx = cJSON_GetObjectItem(jlcore, "rx_lcore_num");
        cJSON *jproc = cJSON_GetObjectItem(jlcore, "process_lcore_num");
        cJSON *jtx = cJSON_GetObjectItem(jlcore, "tx_lcore_num");

        if (!cJSON_IsNumber(jrx) ||
            !cJSON_IsNumber(jproc) ||
            !cJSON_IsNumber(jtx)) {
            dfw_log_write(LOG_ERROR, "load_common_cfg: Invalid lcore config");
            goto __finish;
        }

        dfw_ctx->dfw_lcore_conf.rx_lcore_num = jrx->valueint;
        dfw_ctx->dfw_lcore_conf.process_lcore_num = jproc->valueint;
        dfw_ctx->dfw_lcore_conf.tx_lcore_num = jtx->valueint;
    }

    ret = 0;

__finish:
    if (fp) fclose(fp);
    if (buf) free(buf);
    if (root) cJSON_Delete(root);
    return ret;
}


int dwf_load_cfg(void)
{
    int ret = -1;

    ret = load_eth_cfg();
    if (ret < 0) {
        dfw_log_write(LOG_ERROR, "dfw_load_cfg: load_eth_cfg failed");
        return ret;
    }
    ret = load_route_cfg();
    if (ret < 0) {
        dfw_log_write(LOG_ERROR, "dfw_load_cfg: load_route_cfg failed");
        return ret;
    }

    ret = load_acl_cfg();
    if(ret < 0) {
        dfw_log_write(LOG_ERROR, "dfw_load_cfg: load_acl_cfg failed");
        return ret;
    }

    ret = load_common_cfg();
    if(ret < 0) {
        dfw_log_write(LOG_ERROR, "dfw_load_cfg: load_common_cfg failed");
        return ret;
    }
    return 0;
}
