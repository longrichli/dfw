#ifndef __DFW_DPDK_H__
#define __DFW_DPDK_H__

/*
des:
    dpdk 初始化
param:
    argc: 参数数量(同main函数参数)
    argv: 参数列表
return:
    成功: 0
    失败: -1
*/
int dfw_dpdk_init(int argc, char **argv);

#endif /* __DFW_DPDK_H__ */