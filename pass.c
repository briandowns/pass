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

#define KEY_OVERWRITE_MESSAGE !!!! WARNING !!!!           \
This is a destructive action that will prevent previously \
passwords from being retrieved. Please make sure this is  \
what you want to do.

int encrypt_password(const char *target_file, const char *password, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char buf_in[MAX_PASS_SIZE];
    unsigned char buf_out[MAX_PASS_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_state st;

    unsigned long long out_len;
    unsigned char tag;
    
    FILE *fp_t = fopen(target_file, "wb");

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    
    fwrite(header, 1, sizeof header, fp_t);

    size_t pass_len = strlen(password);
    do {
        tag = EOF ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, password, pass_len, NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!EOF);

    fclose(fp_t);

    return 0;
}

int decrypt_password(const char *source_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char buf_in[MAX_PASS_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buf_out[MAX_PASS_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_state st;

    unsigned long long out_len;
    int eof;
    int ret = -1;
    unsigned char tag;

    FILE *fp_s = fopen(source_file, "rb");
    fread(header, 1, sizeof(header), fp_s);
    
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        goto ret;
    }

    do {
        size_t rlen = fread(buf_in, 1, sizeof buf_in, fp_s);
        
        eof = feof(fp_s);
        
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buf_out, &out_len, &tag, buf_in, rlen, NULL, 0) != 0) {
            goto ret;
        }

        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof) {
            goto ret;
        }

        fwrite(buf_out, 1, (size_t)out_len, stdout);
        fwrite("\n", 1, (size_t)1, stdout);
    } while (!eof);

    ret = 0;
ret:
    fclose(fp_s);
    
    return ret;
}

/**
 * create_key generates a new AES key.
 */
int create_key(const char *key_file)  {
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    crypto_secretstream_xchacha20poly1305_keygen(key);

    FILE *f = fopen(key_file, "w");
    if (!f) {
        return 1;
    }

    fwrite(key, 1, crypto_secretstream_xchacha20poly1305_KEYBYTES, f);
    fclose(f);

    return 0;
}

char* generate_password(const int size) {
    srand(time(NULL));

    char *password = malloc(MAX_PASS_SIZE);

    for(int i = 0; i < size; i++) {
        password[i] = ALL_CHARS[randombytes_random() % (sizeof(ALL_CHARS) - 1)];
    }

    return password;
}

/**
 * in_dict checks to see if the given password is in the 
 * system dictionary.
 */
static bool in_dict(const char *pass) {
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

/** 
 * has_special_char chceks the given password
 * for any special characters.
 */
static bool has_special_char(const char *pass) {
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(SPECIAL_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

/**
 * has_number_char chceks the given password
 * for any number characters.
 */
static bool has_number_char(const char *pass) {
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(NUMBER_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

/**
 * has_upper_char chceks the given password
 * for any upper characters.
 */
static bool has_upper_char(const char *pass) {
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(UPPER_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

/**
 * has_lower_char chceks the given password
 * for any lower characters.
 */
static bool has_lower_char(const char *pass) {
    for (int i = 0; i < strlen(pass); i++) {
        if (strchr(LOWER_CHARS, pass[i]) ) {
            return true;
        }
    }

    return false;
}

void check(const char *pass) {
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
        printf("  y\n");
    } else {
        printf("  n\n");
    }

    return;
}
