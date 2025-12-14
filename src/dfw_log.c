#include <time.h>
#include <stdarg.h>
#include "dfw_log.h"
#include <rte_spinlock.h>

/* 定义 ANSI 转义序列来设置文本颜色 */
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define DEFAULT_LEVEL LOG_DEBUG


static rte_spinlock_t g_log_lock = RTE_SPINLOCK_INITIALIZER;
static char g_log_filename[FILENAME_MAX] = {'\0'};
static logLevel g_level = 0;
void dfw_log_init(logLevel level, char *filename) {
    g_level = level;
    if(filename != NULL) {
        strcpy(g_log_filename, filename);
    } 
}

static void getcurrtime(char *timebuf, size_t len) {
    time_t t = time(NULL);
    struct tm tm_now;
    localtime_r(&t, &tm_now);

    snprintf(timebuf, len,
        "%04d-%02d-%02d %02d:%02d:%02d",
        tm_now.tm_year + 1900,
        tm_now.tm_mon + 1,
        tm_now.tm_mday,
        tm_now.tm_hour,
        tm_now.tm_min,
        tm_now.tm_sec);
}

void dfw_log_write(logLevel level, const char *fmt, ...) {
    if (level < g_level)
        return;

    char buf[1024];
    char timebuf[32];
    int off = 0;

    getcurrtime(timebuf, sizeof(timebuf));

    /* level 前缀 */
    const char *level_str = "INFO";
    const char *color = "";

    switch (level) {
        case LOG_DEBUG:   level_str = "DEBUG"; break;
        case LOG_INFO:    level_str = "INFO";  color = ANSI_COLOR_GREEN; break;
        case LOG_WARNING: level_str = "WARN";  color = ANSI_COLOR_YELLOW; break;
        case LOG_ERROR:   level_str = "ERROR"; color = ANSI_COLOR_RED; break;
    }

    off += snprintf(buf + off, sizeof(buf) - off,
                    "%s%-6s%s [%s]# ",
                    color, level_str, ANSI_COLOR_RESET, timebuf);

    va_list ap;
    va_start(ap, fmt);
    off += vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);

    off += snprintf(buf + off, sizeof(buf) - off, "\n");

    /* === 临界区 === */
    rte_spinlock_lock(&g_log_lock);

    FILE *fp = stdout;
    if (g_log_filename[0]) {
        fp = fopen(g_log_filename, "a");
        if (!fp) {
            rte_spinlock_unlock(&g_log_lock);
            return;
        }
    }

    fwrite(buf, 1, off, fp);
    fflush(fp);

    if (fp != stdout)
        fclose(fp);

    rte_spinlock_unlock(&g_log_lock);
}
