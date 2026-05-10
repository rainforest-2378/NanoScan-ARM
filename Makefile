# 编译器设置 (Mac 上 cc 默认就是 clang)
CC = cc
# 优化选项：-O3 是必须的，-march=native 让编译器针对你的 M1/M2 芯片生成最强代码
CFLAGS = -O3 -march=native -I./include -Wall

# 定义目标文件
SRCS = src/compiler.c src/scanner.c examples/main.c
OBJS = $(SRCS:.c=.o)
TARGET = nanoscan_demo

# 默认规则：编译整个项目
all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

# 编译每个 .c 文件
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理编译结果
clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
