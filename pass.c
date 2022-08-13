
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sodium.h>

#include "pass.h"

#define SPECIAL_CHARS "!@#$%^&*()-_=+,.?/:;{}[]~"
#define NUMBER_CHARS "0123456789"
#define UPPER_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LOWER_CHARS "abcdefghijklmnopqrstuvwxyz"
#define ALL_CHARS UPPER_CHARS LOWER_CHARS NUMBER_CHARS SPECIAL_CHARS

#define WORD_LOCATION "/usr/share/dict/words"

char*
generate_password(const int size)
{
    srand(time(NULL));

    char *password = malloc(MAX_PASS_SIZE);

    for(int i = 0; i < size; i++) {
        password[i] = ALL_CHARS[randombytes_random() % (sizeof(ALL_CHARS) - 1)];
    }

    return password;
}

// in_dict checks to see if the given password is in the 
// system dictionary.
static bool
in_dict(const char *pass)
{
    char line[26];

    FILE *fp = fopen(WORD_LOCATION, "r");
    if (!fp) {
        perror("could not find the file");
        exit(0);
    }

    while (fgets(line, 26, fp) != NULL ) {
        line[strcspn(line, "\r\n")] = 0;

        if (!strcmp(line, pass)) {
            return true;   
        }
    }

    fclose(fp);

    return false;
}

// has_special_char chceks the given password
// for any special characters.
static bool
has_special_char(const char *pass)
{
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(SPECIAL_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

// has_number_char chceks the given password
// for any number characters.
static bool
has_number_char(const char *pass)
{
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(NUMBER_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

// has_upper_char chceks the given password
// for any upper characters.
static bool
has_upper_char(const char *pass)
{
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(UPPER_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

// has_lower_char chceks the given password
// for any lower characters.
static bool
has_lower_char(const char *pass)
{
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(LOWER_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

void
check(const char *pass)
{
    printf("report:\n");

    int score = 0;

    size_t pass_size = strlen(pass);

    printf("  greater than 8:");
    if (pass_size > 8) {
        score++;
        printf(" y\n");
    } else {
        printf(" n\n");
    }

    printf("  has lower:");
    if (has_lower_char(pass)) {
        score++;
        printf("      y\n");
    } else {
        printf("      n\n");
    }

    printf("  has upper:");
    if (has_upper_char(pass)) {
        score++;
        printf("      y\n");
    } else {
        printf("      n\n");
    }

    printf("  has special:");
    if (has_special_char(pass)) {
        score++;
        printf("    y\n");
    } else {
        printf("    n\n");
    }

    printf("  in dictionary:");
    if (in_dict(pass)) {
        score--;
        printf("    y\n");
    } else {
        printf("  n\n");
    }

    return;
}