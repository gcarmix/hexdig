#pragma once
#include <cstdint>
enum : uint32_t {
    FDT_MAGIC       = 0xD00DFEED,
    FDT_BEGIN_NODE  = 0x00000001,
    FDT_END_NODE    = 0x00000002,
    FDT_PROP        = 0x00000003,
    FDT_NOP         = 0x00000004,
    FDT_END         = 0x00000009
};

struct FdtHeader {
    uint32_t magic;
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t size_dt_strings;
    uint32_t size_dt_struct;
};