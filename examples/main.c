#include "nanoscan.h"
#include <string.h>

int main() {
    const char* text = "arm neon is powerful. aim high!";
    ns_pattern_t* pat = ns_compile("a.m");
    
    ns_scan(pat, text, strlen(text));
    
    ns_free(pat);
    return 0;
}
