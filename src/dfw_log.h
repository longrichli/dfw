#ifndef __DFW_LOG_H__
#define __DFW_LOG_H__

typedef enum _mdb_log_level {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
} logLevel;

void dfw_log_init(logLevel level, char *filename);
void dfw_log_write(logLevel level, const char *fmt, ...);



#endif /* __DFW_LOG_H__ */