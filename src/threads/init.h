#ifndef THREADS_INIT_H
#define THREADS_INIT_H

#include <debug.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Page directory with kernel mappings only. */
extern uint32_t *init_page_dir;

/* Returns true if boot has completed */
bool is_boot_complete (void);

#endif /* threads/init.h */
