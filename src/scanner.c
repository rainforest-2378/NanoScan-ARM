#include "nanoscan.h"
#include <stdio.h>

void ns_scan(ns_pattern_t* p, const char* text, size_t len) {
    if (len < p->len) return;

    size_t i = 0;
    // 使用 Overlapping Load 逻辑
    for (; i + 16 + (p->len - 1) <= len; i += 16) {
        uint8x16_t final_mask = vdupq_n_u8(0xFF);
        for (size_t j = 0; j < p->len; j++) {
            if (p->pattern[j] == '.') continue;
            
            uint8x16_t data = vld1q_u8((const uint8_t*)(text + i + j));
            // 直接使用编译阶段准备好的 pat_vecs[j]
            final_mask = vandq_u8(final_mask, vceqq_u8(data, p->pat_vecs[j]));
        }

        if (vaddvq_u8(final_mask) > 0) {
            uint8_t res[16]; vst1q_u8(res, final_mask);
            for (int k = 0; k < 16; k++) {
                if (res[k] == 0xFF) printf("Found at %zu\n", i + k);
            }
        }
    }
    // TODO: Overlapping 逻辑
        for (; i <= len - p->len; i++) {
        int match = 1;
        for (size_t j = 0; j < p->len; j++) {
            if (p->pattern[j] != '.' && text[i + j] != p->pattern[j]) {
                match = 0; break;
            }
        }
        if (match) printf("Found at %zu\n", i);
    }
}
