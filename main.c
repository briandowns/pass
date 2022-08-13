/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2022 Brian J. Downs
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#ifdef __linux__
#include <limits.h>
#else
#include <sys/syslimits.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "pass.h"

#define STR1(x) #x
#define STR(x) STR1(x)

#define USAGE                                                  \
    "usage: %s [-vh]\n"                                        \
    "  -v            version\n"                                \
    "  -h            help\n\n"                                 \
    "commands:\n"                                              \
    "  init          initialize pass\n"                        \
    "  get           retrieve a previously saved password\n"   \
    "  set           save a password\n"                        \
    "  ls,list       list passwords\n"                         \
    "  rm,remove     delete a previously saved password\n"     \
    "  check         checks the given password's complexity\n" \
    "  gen,generate  generates a secure password\n"            \
    "  config        show current configuration\n"             \
    "  help          display the help menu\n"                  \
    "  version       show the version\n"

#define CONFIG_DIR ".pass"
#define KEY_NAME   ".pass.key"
#define IV_NAME    ".pass.iv"

/**
 * BASE_DIRECTORY returns the pass base directory.
 */
#define BASE_DIRECTORY       \
    char base_dir[PATH_MAX]; \
    strcat(strcpy(base_dir, getenv("HOME")), "/" CONFIG_DIR)

/**
 * COMMAND_ARG_ERR_CHECK checks to make sure the 
 * there is an argument to the given command if 
 * if not, print an error and exit.
 */
#define COMMAND_ARG_ERR_CHECK if (argc != 3) {        \
    printf("error: %s requires argument\n", argv[i]); \
    return 1;                                         \
}

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

#define KEY_OVERWRITE_MESSAGE !!!! WARNING !!!!           \
This is a destructive action that will prevent previously \
passwords from being retrieved. Please make sure this is  \
what you want to do.

/**
 * encrypt_password encrypts the given password and saves the
 * encrypted cipher to a file in the user's pass directory.
 */
static int
encrypt_password(const char *target_file, const char *password, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char buf_in[MAX_PASS_SIZE];
    unsigned char buf_out[MAX_PASS_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    
    crypto_secretstream_xchacha20poly1305_state st;

    unsigned long long out_len;
    int eof;
    unsigned char tag;
    
    FILE *fp_t = fopen(target_file, "wb");

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);

    fwrite(header, 1, sizeof header, fp_t);

    do {
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buf_out, &out_len, password, strlen(password), NULL, 0, tag);
        fwrite(buf_out, 1, (size_t)out_len, fp_t);
    } while (!eof);

    fclose(fp_t);

    return 0;
}

/**
 * decrypt_password decrypts the given file and prints out the 
 * contents to stdout.
 */
static int
decrypt_password(const char *source_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
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
static int
create_key(const char *key_file) 
{
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

/**
 * list prints the given directory tree 
 * recursively.
 */
static void
list(const char *name, const int indent)
{
    DIR *dir;
    struct dirent *de;

    if (!(dir = opendir(name))) {
        return;
    }

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') {
                continue;
        }

        if (de->d_type == DT_DIR) {
            char path[PATH_MAX];
            
            if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) {
                continue;
            }
        
            snprintf(path, sizeof(path), "%s/%s", name, de->d_name);
            printf("%*s- %s/\n", indent, "", de->d_name);
            
            list(path, indent + 4);
        } else {
            printf("%*s- %s\n", indent, "", de->d_name);
        }
    }

    closedir(dir);
}

static void
mkdir_p(const char *dir)
{
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = 0;
    for (p = tmp + 1; *p; p++)
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, S_IRWXU);
            *p = '/';
        }
    mkdir(tmp, S_IRWXU);
}

int
main(int argc, char **argv)
{
    if (argc < 2) {
        printf(USAGE, STR(app_name));
        return 1;
    }

    if (sodium_init() != 0) {
        return 1;
    }

    int gen_first = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "version") == 0) {
            printf("version: %s - git: %s\n", STR(app_version), STR(git_sha));
            return 0;
        }

        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "help") == 0) {
            printf(USAGE, STR(bin_name));
            return 0;
        }
            
        char pass_dir_path[PATH_MAX];
        const char *pass_dir = getenv("PASS_DIR");
        if ((pass_dir != NULL) && (pass_dir[0] != 0)) {
            strcpy(pass_dir_path, pass_dir);
        } else {
            strcpy(pass_dir_path, getenv("HOME"));
            strcat(pass_dir_path, "/" CONFIG_DIR);
        }

        char key_file_path[PATH_MAX];
        const char *pass_key = getenv("PASS_KEY");
        if ((pass_key != NULL) && (pass_key[0] == 0)) {
            strcpy(key_file_path, pass_key);
        } else {
            strcpy(key_file_path, pass_dir_path);
            strcat(key_file_path, "/");
            strcat(key_file_path, KEY_NAME);
        }

        if (strcmp(argv[i], "init") == 0) {
            DIR* dir = opendir(pass_dir_path);
            if (ENOENT == errno) {
                printf("creating directory: %s\n", pass_dir_path);
                mkdir(pass_dir_path, 0700);
            } else {
                closedir(dir);
            }
            
            if (access(key_file_path, F_OK ) != -1) {
                char answer;
                printf("overwrite existing key? [Y/n] ");
                scanf("%c", &answer);
                if (answer == 'Y') {
                    printf("creating key: %s\n", key_file_path);
                    if (create_key(key_file_path) != 0) {
                        perror("failed to generate key");
                        return 1;
                    }
                }
            } else {
                printf("creating key: %s\n", key_file_path);
                if (create_key(key_file_path) != 0) {
                    perror("failed to create key");
                    return 1;
                }
            }

            return 0;
        }

        unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];

        FILE *key_fd = fopen(key_file_path, "r");
        fread(&key, crypto_secretstream_xchacha20poly1305_KEYBYTES, 1, key_fd);

        if ((strcmp(argv[i], "ls") == 0) || (strcmp(argv[i], "list") == 0)) {
            if (argc == 3) {
                PASSWORD_FILE_PATH;
                list(fp, 0);
            } else {
                list(pass_dir_path, 0);
            }

            break;
        }

        if (strcmp(argv[i], "set") == 0) {
            COMMAND_ARG_ERR_CHECK;

            char pass_buf[MAX_PASS_SIZE] = {0};
            strcpy(pass_buf, getpass("enter password: "));

            PASSWORD_FILE_PATH;

            if (strchr(fp, '/') != NULL) {
                char *temp_fp = strdup(fp);
                mkdir_p(dirname(temp_fp));
                free(temp_fp);
            }

            if (encrypt_password(fp, pass_buf, key) != 0) {
                return 1;
            }

            break;
        }

        if (strcmp(argv[i], "get") == 0) {
            COMMAND_ARG_ERR_CHECK;
            PASSWORD_FILE_PATH;

            if (access(fp, F_OK ) != -1) {
                if (decrypt_password(fp, key) != 0) {
                    return 1;
                }
            } 

            break;
        }

        if ((strcmp(argv[i], "rm") == 0) || (strcmp(argv[i], "remove") == 0)) {
            COMMAND_ARG_ERR_CHECK;
            PASSWORD_FILE_PATH;

            remove(fp);

            break;
        }

        if (strcmp(argv[i], "config") == 0) {
            printf("path: %s\n", pass_dir_path);
            printf("key : %s\n", key_file_path);
            break;
        }

        if (strcmp(argv[i], "generate") == 0) {
            COMMAND_ARG_ERR_CHECK;

            int size = atoi(argv[2]);
            char *pass = generate_password(size);

            printf("%s\n", pass);
            free(pass);

            break;
        }

        if (strcmp(argv[i], "check") == 0) {
            COMMAND_ARG_ERR_CHECK;

            check(argv[2]);

            break;
        }
    }

    return 0;
}

