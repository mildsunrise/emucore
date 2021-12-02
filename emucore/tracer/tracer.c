#include <stdint.h>
#include <stddef.h>

#define UC_ERR_OK 0
typedef int uc_err;
typedef struct uc_struct uc_engine;
// populated in Python side to avoid loading problems
uc_err (*uc_reg_read)(uc_engine *uc, int regid, void *value) = NULL;

#define UC_X86_REG_RSP 44

// code

typedef struct trace_entry {
    uint64_t sp;
    uint64_t ip;
} trace_entry;

typedef struct trace_data {
    size_t capacity;
    size_t size;
    trace_entry *entries;
} trace_data;

void hook_block(uc_engine *uc, uint64_t addr, uint32_t size, void *_data) {
    trace_data *data = (trace_data *)_data;

    uint64_t sp;
    int err = uc_reg_read(uc, UC_X86_REG_RSP, &sp);
    if (err != UC_ERR_OK) return;

    while (data->size && data->entries[data->size-1].sp <= sp)
        data->size--;
    trace_entry entry = { sp, addr + size };
    if (data->size < data->capacity)
        data->entries[data->size++] = entry;
}
