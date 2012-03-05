#include "libmonkey.h"
#include <stdio.h>
#include <assert.h>

int injected_function(int a, int b, int c)
{
    printf("I am the injected function!\n");
    return a-b-c;
}

static void
__attribute__((constructor))
do_inject(void)
{
    libmonkey_t my_monkey = libmonkey_new_from_exe();
    assert(libmonkey_patch(my_monkey, "some_function",
            injected_function, NULL, NULL) == 0);
    libmonkey_free(my_monkey);
}
