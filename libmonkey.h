#ifndef MONKEY_H_
#define MONKEY_H_
#include <sys/types.h>

int some_function(int,int,int);
int libmonkey_override_by_ptr(void *orig, const void *target);

struct libmonkey_st {
    void *addr;
    size_t maplen;
    int fd;
};

typedef struct libmonkey_st* libmonkey_t;


/**
 * These functions will replace a non-static symbol with anything you want,
 * provided the symbol can be located by its name AND you are using the ELF
 * format.
 */

/* This returns a handle based on the current running executable */
libmonkey_t libmonkey_new_from_exe(void);

/* Returns a new handle based on the path */
libmonkey_t libmonkey_new_from_path(const char *path);

/* Replaces the global symbol victim with the function
 * found at injection.
 * If old is not-null, the raw code previously beloning to the victim
 * function will be placed there.
 */
int libmonkey_patch(libmonkey_t monkey,
                    const char *victim,
                    const void *injection,
                    void **old,
                    size_t *nold);

/*
 * Free the libmonkey structure
 */
void libmonkey_free(libmonkey_t monkey);

#endif /* MONKEY_H_ */
