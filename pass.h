#ifndef __PASS_H
#define __PASS_H

#include <string.h>

#include <sodium.h>

#define MAX_PASS_SIZE 4096

/**
 * BASE_DIRECTORY returns the pass base directory.
 */
#define BASE_DIRECTORY       \
    char base_dir[PATH_MAX]; \
    strcat(strcpy(base_dir, getenv("HOME")), "/" CONFIG_DIR)

/**
 * PASSWORD_FILE_PATH creates a string containing the 
 * path to the password file derived from the given
 * argument.
 */
#define PASSWORD_FILE_PATH char fp[PATH_MAX] = {0}; \
BASE_DIRECTORY;                                     \
strcpy(fp, base_dir);                               \
strcat(fp, "/");                                    \
strcat(fp, argv[i+1]);

/**
 * encrypt_password encrypts the given password and saves the
 * encrypted cipher to a file in the user's pass directory.
 */
int encrypt_password(const char *target_file, const char *password, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

/**
 * decrypt_password decrypts the given file and prints out the 
 * contents to stdout.
 */
int decrypt_password(const char *source_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]);

int create_key(const char *key_file);

/** 
 * generate creates a password with the given size. The 
 * returned string will need to be freed by the caller.
 */
char* generate_password(const int size);

/**
 * check checks to see if the given password meets 
 * complexity requirements for upper, lower, numbers,
 * special characters, and dictionary words.
 */
void check(const char *pass);

#endif /* __PASS_H  */
