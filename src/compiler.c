#include "nanoscan.h"
#include <stdlib.h>
#include <string.h>

ns_pattern_t* ns_compile(const char* re) {
    ns_pattern_t* p = malloc(sizeof(ns_pattern_t));
    p->len = strlen(re);
    p->pattern = strdup(re);
    
    // 提前为每个字符准备好 vdupq_n_u8 的向量
    p->pat_vecs = malloc(sizeof(uint8x16_t) * p->len);
    for (size_t i = 0; i < p->len; i++) {
        p->pat_vecs[i] = vdupq_n_u8(re[i]);
    }
    return p;
}

void ns_free(ns_pattern_t* p) {
    free(p->pattern);
    free(p->pat_vecs);
    free(p);
}
