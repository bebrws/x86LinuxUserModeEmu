#ifndef VDSO_H
#define VDSO_H

#define VDSO_PAGES 1

extern const char vdso_data[] __asm__("vdso_data_start");
//extern const char vdso_data[VDSO_PAGES * (1 << 12)] __asm__("_vdso_data");
//extern const char *vdso_data_start;// __asm__("_vdso_data");
//const char *vdso_data = &vdso_data_start;
int vdso_symbol(const char *name);

#endif
