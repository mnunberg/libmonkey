#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int some_function(int a, int b, int c)
{
    printf("I am the original function\n");
    return a + b +c;
}

int execute_program(const char *path)
{
    printf("Invoking execve @%p\n", execve);
    execve(path, NULL, NULL);
}

int main(void) {
    int ret = some_function(1,2,3);
    printf("Returned: %d\n", ret);
    execute_program("/bin/true");
    return 0;
}
