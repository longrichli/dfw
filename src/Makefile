# 变量定义
CC = gcc

PKGCONF ?= pkg-config
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif
CFLAGS = -Wall $(shell $(PKGCONF) --cflags libdpdk 2>/dev/null)
TARGET = dfw


CLIBS = $(shell $(PKGCONF) --libs libdpdk 2>/dev/null)
# 自动查找当前目录下的所有 .c 文件
SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

# 默认目标
all: $(TARGET)

# 链接目标文件
$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(CLIBS)

# 编译 .c 文件为 .o 文件（模式规则）
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理目标
clean:
	rm -f $(TARGET) $(OBJS)

.PHONY: all clean