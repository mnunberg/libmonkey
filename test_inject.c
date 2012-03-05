#include "libmonkey.h"
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>

int injected_function(int a, int b, int c)
{
    printf("I am the injected function!\n");
    return a-b-c;
}

int myexecve(const char *path, char **argv, char **envp)
{
    printf("I am executing path %s\n", path);
    return syscall(SYS_execve, path, argv, envp);
}

static void
__attribute__((constructor))
do_inject(void)
{
    libmonkey_t my_monkey = libmonkey_new_from_exe();
    assert(libmonkey_patch(my_monkey, "some_function",
            injected_function, NULL, NULL) == 0);
    libmonkey_patch(my_monkey, "execve", myexecve, NULL, NULL);
    libmonkey_free(my_monkey);
}
