/**
 * Copyright (C) 2022 Singular Security Lab
 * Author: XiaoLu
 * Create: 2022-03
 */
#include "../include/config.h"
#include "../include/types.h"


u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
    __afl_area_ptr[*guard]++;
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {
    int inst_ratio = 100;
    
    if (start == stop || *start) return;
    
    *(start++) = R(MAP_SIZE - 1) + 1;
    
    while (start < stop) {
        if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
        else *start = 0;
        start++;
    }
}