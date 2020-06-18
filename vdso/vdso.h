#ifndef VDSO_H
#define VDSO_H

#define VDSO_PAGES 1

extern const char vdso_data[VDSO_PAGES * (1 << 12)] __asm__("vdso_data_start");

int vdso_symbol(const char *name);

#endif
