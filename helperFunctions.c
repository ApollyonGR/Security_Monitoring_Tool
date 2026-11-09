#include <stdio.h>
#include <string.h>
#include "security_event.h"

// shorthand for Print and Prompt, a helper function that handles user input and it's validation
int pnp(const char *prompt, char *dest, size_t size) {
    printf("\n%s", prompt);
    fgets(dest, size, stdin);
    dest[strcspn(dest, "\n")] = '\0'; // replaces second \n with \0 after fgets

    return strcmp(dest, "q") != 0; // returns one if it's a search term, or 0 if it's q
}

int clearStdin(void) {
    for (int c; (c = getchar()) != '\n' && c != EOF;); // removes first \n before fgets
    return 0;
}