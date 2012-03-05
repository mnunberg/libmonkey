#include <stdio.h>
#include <stdlib.h>

int some_function(int a, int b, int c)
{
    printf("I am the original function\n");
    return a + b +c;
}

int main(void) {
    int ret = some_function(1,2,3);
    printf("Returned: %d\n", ret);
    return 0;
}
