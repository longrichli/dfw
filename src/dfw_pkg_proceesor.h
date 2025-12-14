#ifndef __DFW_PKG_PROCESSOR_H__
#define __DFW_PKG_PROCESSOR_H__

typedef enum _dfw_pkg_process_result {
    DFW_PKG_PROCESS_RESULT_DO_NOT_FORWARD = -2,
    DFW_PKG_PROCESS_RESULT_DROP = -1,
    DFW_PKG_PROCESS_RESULT_FORWARD = 0,
} dfwPkgProcessResult;

int dfw_pkg_process_loop(void *arg);

#endif /* __DFW_PKG_PROCESSOR_H__ */