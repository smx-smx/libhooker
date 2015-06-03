#ifndef __LH_MODULE_COMMON_H
#define __LH_MODULE_COMMON_H
#include <stdint.h>

const char *addr2sym(uintptr_t addr);
lh_r_process_t *lh_get_procinfo(int argc, char **argv);
int lh_get_stdout(char *tty);
void lh_printf(const char *fmt, ...);
void lh_stdout_clear();
int lh_stdout_getcurrent();
void lh_stdout_set(int fd);
void lh_vaprintf(const char *fmt, va_list ap);
void lhm_hexdump(uintptr_t address, size_t size);
uintptr_t lhm_memcpy(uintptr_t dst_address, uintptr_t src_address);
uintptr_t lhm_mmap(uintptr_t address, size_t size);
int lhm_munmap(uintptr_t address, size_t size);
void *sym2addr(const char *name);
uintptr_t symfile_addr_by_name(const char *name);
int symfile_load(const char *fname);
const char *symfile_name_by_addr(uintptr_t addr);


#endif