#ifndef NANOSCAN_H
#define NANOSCAN_H

#include <stdint.h>
#include <stddef.h>
#include <arm_neon.h>

// 编译后的模式结构
typedef struct {
    uint8_t *pattern;
    uint8x16_t *pat_vecs; // 预分配的 NEON 寄存器组
    size_t len;
} ns_pattern_t;

// 编译接口：把正则字符串转为内部格式
ns_pattern_t* ns_compile(const char* re);

// 扫描接口：在 text 中搜索 p
void ns_scan(ns_pattern_t* p, const char* text, size_t len);

// 释放内存
void ns_free(ns_pattern_t* p);

#endif
