#include <stdio.h>
#include <string.h>
#include <stdlib.h>

volatile int secret = 0x41424344;

void win_function(void) {
    printf("FLAG{x1_binrecon_compiled_target}\n");
}

void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);
    printf("buf: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable(argv[1]);
    } else {
        printf("Usage: %s <input>\n", argv[0]);
    }
    return 0;
}
