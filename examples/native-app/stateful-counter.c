/* Source-owned end-to-end fixture. The original process owns both state cells. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

static int32_t current = 7;
static int32_t previous = 7;

__attribute__((noinline)) int32_t stateful_step(int32_t operation, int32_t amount) {
    if (operation == 1) {
        previous = current;
        current += amount; /* Compiled with -fwrapv: signed32 wrap is deliberate. */
    } else if (operation == 2) {
        previous = current;
        current = amount;
    } else if (operation == 3) {
        int32_t saved = current;
        current = previous;
        previous = saved;
    }
    return current;
}

static void spaces(char **p) { while (isspace((unsigned char)**p)) ++*p; }
static int token(char **p, char c) { spaces(p); if (**p != c) return 0; ++*p; return 1; }
static int number(char **p, int32_t *value) {
    spaces(p); char *end; errno = 0;
    long long parsed = strtoll(*p, &end, 10);
    if (end == *p || errno || parsed < INT32_MIN || parsed > INT32_MAX) return 0;
    *p = end; *value = (int32_t)parsed; return 1;
}
int main(void) {
    static char input[1048577];
    size_t size = fread(input, 1, sizeof(input)-1, stdin);
    if (ferror(stdin) || !feof(stdin)) return 2;
    input[size] = 0; char *p = input; int32_t steps[64][2]; size_t count = 0;
    if (!token(&p, '[')) return 2;
    do {
        if (count == 64 || !token(&p, '[') || !number(&p, &steps[count][0]) ||
            !token(&p, ',') || !number(&p, &steps[count][1]) || !token(&p, ']')) return 2;
        ++count; spaces(&p);
        if (*p != ',') break;
        ++p;
    } while (1);
    if (!token(&p, ']')) return 2;
    spaces(&p); if (*p) return 2;
    fputs("[", stdout);
    for (size_t i=0; i<count; ++i) {
        if (i) fputs(",", stdout);
        printf("{\"kind\":\"return\",\"value\":%d}", (int)stateful_step(steps[i][0],steps[i][1]));
    }
    puts("]"); return 0;
}
