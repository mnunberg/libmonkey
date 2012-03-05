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
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/mman.h>

#include "libmonkey.h"

static int Libmonkey_Debug = 0;

static void
__attribute__((constructor))
init_debug(void)
{
    const char *envar = getenv("LIBMONKEY_DEBUG");
    if(envar) {
        sscanf(envar, "%d", &Libmonkey_Debug);
    }
}

#define DEBUG_MSG(lvl, ...) \
    if(lvl <= Libmonkey_Debug) { \
    fprintf(stderr, "LIBMONKEY: "); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    }

#define DUMP_SHDR(...) \
    if(Libmonkey_Debug >= 5) { dump_shdr(__VA_ARGS__); }

#define DUMP_SYMENT(...) \
    if(Libmonkey_Debug >= 5) { dump_syment(__VA_ARGS__); }

static inline void dump_shdr(ElfW(Shdr) *shdr, const char *name, size_t ii)
{
    if (name == NULL) {
        name = "";
    }
    fprintf(stderr, "SECTION: \"%s\": "
            "idx=%lu, type=%"PRIx64 " , flags=%"PRIx64", info=%"PRIx32"\n",
            name,
            ii,
            (uint64_t)shdr->sh_type,
            (uint64_t)shdr->sh_flags,
            (uint32_t)shdr->sh_info);

}

static inline void dump_syment(ElfW(Sym) *syment, const char *name)
{
    if (name == NULL) {
        name = "";
    }
    fprintf(stderr, "SYMBOL: \"\%s\" ndx=%d @%p [%luB]\n",
            name,
            syment->st_shndx,
            (void*)syment->st_value,
            syment->st_size);
}

int libmonkey_patch(libmonkey_t monkey,
                    const char *victim,
                    const void *injection,
                    void **old,
                    size_t *nold)
{
    void *mapaddr = monkey->addr;
    ElfW(Ehdr) *ehdr = mapaddr;
    ElfW(Shdr) *shdr, *sym_shdr = NULL, *dynsym_shdr = NULL;
    ElfW(Sym) *syments = NULL;
    ElfW(Sym) *symvictim = NULL;

    char *strtable, *symstrs = NULL, *dynsymstrs = NULL;
    size_t ii;
    size_t stridx;
    size_t nsyms;

    stridx = ehdr->e_shstrndx;

    DEBUG_MSG(5, "String table index=%d", ehdr->e_shstrndx);

    shdr = mapaddr + ehdr->e_shoff;
    strtable = mapaddr + shdr[stridx].sh_offset;

    for (ii = 0; ii < ehdr->e_shnum; ii++) {
        const char *section_name = "";
        size_t nameidx = shdr[ii].sh_name;

        if (nameidx) {
            section_name = strtable + nameidx;
        }

        DUMP_SHDR(shdr + ii, section_name, ii);

        switch(shdr[ii].sh_type) {
        case SHT_SYMTAB:
            sym_shdr = shdr + ii;
            break;
        case SHT_DYNSYM:
            dynsym_shdr = shdr + ii;
            break;
        case SHT_STRTAB: {
            char *some_strtbl = mapaddr + (ptrdiff_t)shdr[ii].sh_offset;
            if (strcmp(section_name, ".strtab") == 0) {
                symstrs = some_strtbl;
            } else if (strcmp(section_name, ".dynstr") == 0) {
                dynsymstrs = some_strtbl;
            }
            break;
        }
        default:
            break;
        }
    }


    if (sym_shdr == NULL) {
        if (dynsym_shdr) {
            DEBUG_MSG(3, "Couldn't find symbol in .symtab. Using .dynsym");
            sym_shdr = dynsym_shdr;
            symstrs = dynsymstrs;
        } else {
            DEBUG_MSG(1, "Couldn't find symbol table!");
            return -1;
        }
    }

    if (symstrs == NULL) {
        DEBUG_MSG(1, "Couldn't find symbol string table");
        return -1;
    }

    nsyms = sym_shdr->sh_size / sizeof(ElfW(Sym));
    syments = mapaddr + sym_shdr->sh_offset;

    DEBUG_MSG(3, "Will analyze symbols");

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
        DUMP_SYMENT(syments + ii, symname);

        if (strcmp(symname, victim) == 0) {
            DEBUG_MSG(1, "Found function to override (@%p, [%luB]!",
                      (void*)syments[ii].st_value, syments[ii].st_size);
            symvictim = syments + ii;
            break;
        }
    }

    if (!symvictim) {
        DEBUG_MSG(1, "LIBMONKEY: couldn't find symbol \"%s\"", victim);
        return -1;
    }

    if (!symvictim->st_value) {
        DEBUG_MSG(1, "LIBMONKEY: Symbol \"%s\" referenced but not defined", victim);
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
