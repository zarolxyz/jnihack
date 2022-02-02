#include<stdint.h>

uintptr_t GetLibraryAddress(char *name);
void UnprotectPage(void *addr);
void ARMHook(void *dest, void *addr);
void THUMBHook(void *dest, void *addr);
