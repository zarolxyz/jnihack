#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/mman.h>
#include"util.h"

uintptr_t GetLibraryAddress(char *name)
{
	uintptr_t addr = 0;
        FILE *fp = fopen("/proc/self/maps", "r");
        char buf[512];
        while(fgets(buf, 512, fp) != NULL)
        {
                if(strstr(buf, name) != NULL)
                {
                        addr = strtoul(buf, NULL, 16);
                        break;
                }
        }
        fclose(fp);
	return addr;
}

void UnprotectPage(void *addr)
{
	mprotect((void *)((uintptr_t)addr & 0xfffff000), 4096 * 2, PROT_READ | PROT_WRITE | PROT_EXEC);
}

void ARMHook(void *dest, void *addr)
{
        ((char *)dest)[0] = 0x00;
        ((char *)dest)[1] = 0xf0;
        ((char *)dest)[2] = 0x9f;
        ((char *)dest)[3] = 0xe5;
        *(uint32_t *)(dest + 8) = (uint32_t)addr;
}

void THUMBHook(void *dest, void *addr)
{
	dest = (void *)((uint32_t)dest &~ 1);
	uint16_t addrl = ((uint32_t)addr & 0xffff) | 1;
	uint16_t addrh = (uint32_t)addr >> 16;
	((char *)dest)[0] = 0x40 | ((addrl & 0xf000) >> 12);
        ((char *)dest)[1] = 0xf2 | ((addrl & (1 << 11)) >> 9);
        ((char *)dest)[2] = addrl & 0xff;
        ((char *)dest)[3] = 0x0c | ((addrl & (0x7 << 8)) >> 4);
	((char *)dest)[4] = 0xc0 | ((addrh & 0xf000) >> 12);
        ((char *)dest)[5] = 0xf2 | ((addrh & (1 << 11)) >> 9);
        ((char *)dest)[6] = addrh & 0xff;
        ((char *)dest)[7] = 0x0c | ((addrh & (0x7 << 8)) >> 4);
	((char *)dest)[8] = 0x60;
	((char *)dest)[9] = 0x47;
}
