#ifdef __linux__
#include <link.h>
#include <elf.h>
#else
#include <libelf.h>
#define ElfW(x) Elf64_ ## x
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>

#include "libmonkey.h"

int libmonkey_patch(libmonkey_t monkey,
                    const char *victim,
                    const void *injection,
                    void **old,
                    size_t *nold)
{
    const void *mapaddr = monkey->addr;
    ElfW(Ehdr) *ehdr = mapaddr;
    ElfW(Shdr) *shdr, *sym_shdr = NULL, *dynsym_shdr = NULL;
    ElfW(Sym) *syments = NULL;
    ElfW(Sym) *symvictim = NULL;

    char *strtable, *symstrs = NULL, *dynsymstrs = NULL;
    size_t ii;
    size_t stridx;
    size_t nsyms;

    stridx = ehdr->e_shstrndx;

    printf("String Table Index=%d\n", ehdr->e_shstrndx);

    shdr = mapaddr + ehdr->e_shoff;
    strtable = mapaddr + shdr[stridx].sh_offset;

    for (ii = 0; ii < ehdr->e_shnum; ii++) {
        size_t nameidx = shdr[ii].sh_name;
        char *section_name = strtable + nameidx;
        printf("\nSection idx=%lu, nameidx=%lx, type=%x, flags=%x, info=%x\n",
                ii,
                nameidx,
                shdr[ii].sh_type,
                shdr[ii].sh_flags,
                shdr[ii].sh_info);
        if (nameidx) {
            printf("\tName is %s\n", section_name);
        }

        if (shdr[ii].sh_type == SHT_SYMTAB) {
            sym_shdr = shdr + ii;
        } else if(shdr[ii].sh_type == SHT_DYNSYM) {
            dynsym_shdr = shdr + ii;
        } else if (shdr[ii].sh_type == SHT_STRTAB &&
                strcmp(section_name, ".strtab") == 0) {
            printf("Found symbol string table!\n");
            symstrs = mapaddr + (size_t)shdr[ii].sh_offset;
        } else if (shdr[ii].sh_type == SHT_STRTAB &&
                strcmp(section_name, ".dynstr") == 0) {
            printf("Found .dynstr\n");
            dynsymstrs = mapaddr + (size_t)shdr[ii].sh_offset;
        }
    }


    if (sym_shdr == NULL) {
        if (dynsym_shdr) {
            printf("Using .dynsym instead\n");
            sym_shdr = dynsym_shdr;
            symstrs = dynsymstrs;
        } else {
            printf("Couldn't find symbol table. Aborting\n");
            abort();
        }
    }

    if (symstrs == NULL) {
        printf("Couldn't find symbol string table!\n");
        abort();
    }

    nsyms = sym_shdr->sh_size / sizeof(ElfW(Sym));
    syments = mapaddr + sym_shdr->sh_offset;


    printf("\n\nLooking At symbols\n\n");

    for (ii = 0; ii < nsyms; ii++) {
        char *symname;
        size_t nameidx = syments[ii].st_name;
        if (nameidx == 0
                || syments[ii].st_value == 0
                || syments[ii].st_info == STT_SECTION
                || syments[ii].st_info == STT_FILE) {
            continue;
        }
        symname = symstrs + nameidx;
        printf("Symbol name=%s, shndx=%d, addr=%x, sz=%lu\n",
                symname,
                syments[ii].st_shndx,
                syments[ii].st_value,
                syments[ii].st_size);

        if (strcmp(symname, victim) == 0) {
            printf("Found function to override!\n");
            symvictim = syments + ii;
            break;
        }
    }

    if (!symvictim) {
        fprintf(stderr, "LIBMONKEY: couldn't find symbol \"%s\"\n", victim);
        return -1;
    }

    if (!symvictim->st_value) {
        fprintf(stderr, "LIBMONKEY: Symbol \"%s\" referenced but not defined\n", victim);
        return -1;
    }

    if (old) {
        *old = malloc(symvictim->st_size);
        memcpy(*old, (void*)symvictim->st_value, symvictim->st_size);
        *nold = symvictim->st_size;
    }

    {
        int ybret = libmonkey_override_by_ptr(
                (void*)symvictim->st_value, injection);
        if (ybret == 1) {
            return 0;
        } else {
            return -1;
        }
    }

    return 0xdeadbeef; /*not reached*/

}

libmonkey_t libmonkey_new_from_exe(void)
{
    char path[4096];
    pid_t my_pid = getpid();
    sprintf(path, "/proc/%d/exe", my_pid);
    return libmonkey_new_from_path(path);
}

libmonkey_t libmonkey_new_from_path(const char *path)
{
    struct libmonkey_st *ret = malloc(sizeof(struct libmonkey_st));
    struct stat sb;
    ret->fd = open(path, O_RDONLY);

    if (ret->fd < 0) {
        fprintf(stderr, "LIBMONKEY: %s: %s\n", path, strerror(errno));
        free(ret);
        return NULL;
    }

    assert( fstat(ret->fd, &sb) == 0);
    ret->maplen = sb.st_size;

    assert( (ret->addr =
            mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, ret->fd, 0)) != NULL);

    return ret;
}

void libmonkey_free(libmonkey_t monkey)
{
    close(monkey->fd);
    munmap(monkey->addr, monkey->maplen);
    free(monkey);
}
