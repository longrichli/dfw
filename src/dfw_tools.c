#include "dfw_tools.h"
#include "dfw_log.h"
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <rte_byteorder.h>
#include <rte_eal.h>


/*
des:
    如果目录不存在,创建目录
param:
    dirname: 目录名
return:
    成功: 0
    失败: 小于 0 的错误码
*/
static int create_dir(const char *dirname) {
    int tmp_ret = -1;
    int ret = -1;
    struct stat sa;
    memset(&sa, 0, sizeof(sa));
    if((tmp_ret = stat(dirname, &sa)) < 0) {
        if(errno == ENOENT) {
            if((tmp_ret = mkdir(dirname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) < 0) {
                dfw_log_write(LOG_ERROR, "create_dir() mkdir() errcode[%d] | At %s:%d", tmp_ret, __FILE__, __LINE__);
                goto __finish;
            }
        } else {
                dfw_log_write(LOG_ERROR, "create_dir() stat() errcode[%d] | At %s:%d", tmp_ret, __FILE__, __LINE__);
                goto __finish;
        }
    } 
    ret = 0;
__finish:
    return ret;
}

/*
des:
    根据指定的mode创建文件
param:
    filename: 文件名
    mode: 创建模式: 
        r	打开一个已有的文本文件，允许读取文件。
        w	打开一个文本文件，允许写入文件。如果文件不存在，
            则会创建一个新文件。在这里，您的程序会从文件的
            开头写入内容。如果文件存在，则该会被截断为零长度，
            重新写入。
        a	打开一个文本文件，以追加模式写入文件。如果文件不
            存在，则会创建一个新文件。在这里，您的程序会在已
            有的文件内容中追加内容。
        r+	打开一个文本文件，允许读写文件。
        w+	打开一个文本文件，允许读写文件。如果文件已存在，
            则文件会被截断为零长度，如果文件不存在，则会创建
            一个新文件。
        a+	打开一个文本文件，允许读写文件。如果文件不存在，
        则会创建一个新文件。读取会从文件的开头开始，写入则
        只能是追加模式。
return:
    成功: 文件指针
    失败: NULL
*/
static FILE *create_file(const char *filename, const char *mode) {
    FILE *fp = NULL;
    if(filename == NULL || filename[0] == '\0' || mode == NULL || mode[0] == '\0') {
        dfw_log_write(LOG_ERROR, "create_file() | At %s:%d", __FILE__, __LINE__);
        return NULL;
    }
    if((fp = fopen(filename, mode)) == NULL) {
        dfw_log_write(LOG_ERROR, "create_file() fopen() | At %s:%d", __FILE__, __LINE__);
        return NULL;
    }
    return fp;
}

/*
des:
    根据指定的mode创建文件, 文件名可以存在多级目录, 如: /root/a/b/c.txt
param:
    filename: 文件名
    mode: 创建模式: 
        r	打开一个已有的文本文件，允许读取文件。
        w	打开一个文本文件，允许写入文件。如果文件不存在，
            则会创建一个新文件。在这里，您的程序会从文件的
            开头写入内容。如果文件存在，则该会被截断为零长度，
            重新写入。
        a	打开一个文本文件，以追加模式写入文件。如果文件不
            存在，则会创建一个新文件。在这里，您的程序会在已
            有的文件内容中追加内容。
        r+	打开一个文本文件，允许读写文件。
        w+	打开一个文本文件，允许读写文件。如果文件已存在，
            则文件会被截断为零长度，如果文件不存在，则会创建
            一个新文件。
        a+	打开一个文本文件，允许读写文件。如果文件不存在，
        则会创建一个新文件。读取会从文件的开头开始，写入则
        只能是追加模式。
        如果处理的是二进制文件，则需使用下面的访问模式来取代上面的访问模式：
        "rb", "wb", "ab", "rb+", "r+b", "wb+", "w+b", "ab+", "a+b"
return:
    成功: 文件指针
    失败: NULL
*/
FILE *dfw_create_file(const char *filename, const char *mode) {
    int ret = -1;
    int tmp_ret = -1;
    char *cur_token = NULL;
    char *pre_token = NULL;
    char cwd[FILENAME_MAX] = {0};
    FILE *fp = NULL;
    char *cwd_ptr = cwd;
    char filename_dup[FILENAME_MAX] = {0};
    if(filename == NULL || filename[0] == '\0' || mode == NULL || mode[0] == '\0') {
        dfw_log_write(LOG_ERROR, "dfw_create_file() | At %s:%d", __FILE__, __LINE__);
        goto __finish;
    }
    /* 保存当前目录 , 因为后面创建多级目录时, 改变工作目录, 所以为了回来, 先保存起来 */
    cwd_ptr = getcwd(cwd, FILENAME_MAX);
    if(cwd_ptr == NULL) {
        dfw_log_write(LOG_ERROR, "dfw_create_file() getcwd() | At %s:%d", __FILE__, __LINE__);
        goto __finish;
    }
    /* 使用filename 副本进行操作 */
    strcpy(filename_dup, filename);
    /* 如果第一个字符就是 '/', 说明是从跟目录开始, 应该切换到根目录进行创建 */
    if(filename_dup[0] == '/' || filename_dup[0] == '\\') {
        chdir("/");
    }
    pre_token = strtok(filename_dup, "/\\");
    while(pre_token != NULL) {
        cur_token = strtok(NULL, "/\\");
        if(cur_token == NULL) {
            /* 说明pre_token是一个文件, 进行创建文件, 如果文件已经存在, 避免覆盖重要数据, 不进行创建, 返回错误 */
            if((fp = create_file(pre_token, mode)) == NULL) {
                dfw_log_write(LOG_ERROR, "dfw_create_file() create_file() | At %s:%d",
                             __FILE__, __LINE__);
                goto __finish;
            }
        } else {
            /* 说明pre_token是一个目录, 进行创建目录, 如果目录存在, 什么也不做 */
            if((tmp_ret = create_dir(pre_token)) < 0) {
                dfw_log_write(LOG_ERROR, "dfw_create_file() create_dir() errcode[%d] | At %s:%d",
                            tmp_ret, __FILE__, __LINE__);
                goto __finish;
            }
            chdir(pre_token);
        }
        pre_token = cur_token;
    }

    /* 切换回开始的工作目录*/
    chdir(cwd_ptr);
    ret = 0;
__finish:
    return ret == 0 ? fp : NULL;
}


uint64_t ms_to_tsc(uint64_t ms)
{
    return ms * (rte_get_tsc_hz() / 1000);
}


int dfw_parse_port_range(const char *port_str,
                     uint16_t *min_port,
                     uint16_t *max_port)
{
    assert(port_str && min_port && max_port);

    char *dash = strchr(port_str, '-');

    errno = 0;

    if (!dash) {
        /* single port: "80" */
        char *end = NULL;
        long port = strtol(port_str, &end, 10);

        if (errno != 0 || end == port_str || *end != '\0')
            return -1;

        if (port < 0 || port > 65535)
            return -1;

        *min_port = (uint16_t)rte_cpu_to_be_16(port);
        *max_port = (uint16_t)rte_cpu_to_be_16(port);
        return 0;
    }

    /* range: "1000-2000" */
    char left[16]  = {0};
    char right[16] = {0};

    size_t left_len = dash - port_str;
    size_t right_len = strlen(dash + 1);

    if (left_len == 0 || right_len == 0 ||
        left_len >= sizeof(left) ||
        right_len >= sizeof(right))
        return -1;

    memcpy(left, port_str, left_len);
    memcpy(right, dash + 1, right_len);

    char *end1 = NULL;
    char *end2 = NULL;

    long pmin = strtol(left, &end1, 10);
    long pmax = strtol(right, &end2, 10);

    if (errno != 0 ||
        end1 == left || *end1 != '\0' ||
        end2 == right || *end2 != '\0')
        return -1;

    if (pmin < 0 || pmin > 65535 ||
        pmax < 0 || pmax > 65535 ||
        pmin > pmax)
        return -1;

    *min_port = (uint16_t)rte_cpu_to_be_16(pmin);
    *max_port = (uint16_t)rte_cpu_to_be_16(pmax);

    return 0;
}


