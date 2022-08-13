#include <string.h>

#include <sodium.h>
#include <zlib.h>

#include "backup.h"
#include "pass.h"

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        exit(1); \
    } \
}

static int
encrypt_archive(const char *in_file, const char *out_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char bufferIn[MAX_PASS_SIZE];
    unsigned char bufferOut[MAX_PASS_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_state st;
    FILE *openout_file, *openin_file;
    unsigned long long outputLen;
    size_t readLen;
    int eof;
    unsigned char tag;

    openin_file = fopen(in_file, "rb");
    openout_file = fopen(out_file, "wb");

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);

    fwrite(header, 1, sizeof header, openout_file);
    do {
        readLen = fread(bufferIn, 1, sizeof bufferIn, openin_file);
        eof = feof(openin_file);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, bufferOut, &outputLen, bufferIn, readLen, NULL, 0, tag);
        fwrite(bufferOut, 1, (size_t) outputLen, openout_file);
    } while (!eof);

    fclose(openout_file);
    fclose(openin_file);

    return 0;
}

int decrypt_file(const char *fileToDecrypt, const char *outputFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES]) {
    unsigned char bufferIn[MAX_PASS_SIZE];
    unsigned char bufferOut[MAX_PASS_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];

    crypto_secretstream_xchacha20poly1305_state st;
    FILE *openOutputFile, *openFileToDecrypt;
    unsigned long long outputLen;
    size_t readLen;
    int eof;
    int ret = -1;
    unsigned char tag;

    log_debug("Opening file to decrypt in rb mode");
    openFileToDecrypt = fopen(fileToDecrypt, "rb");
    log_debug("Opening output file in wb mode");
    openOutputFile = fopen(outputFile, "wb");
    fread(header, 1, sizeof header, openFileToDecrypt);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, generatedCryptoKey) != 0) {
        goto ret; /* incomplete header */
    }
    do {
        readLen = fread(bufferIn, 1, sizeof bufferIn, openFileToDecrypt);
        eof = feof(openFileToDecrypt);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, bufferOut, &outputLen, &tag, bufferIn, readLen, NULL, 0) != 0) {
            goto ret; /* corrupted chunk */
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            goto ret; /* premature end (end of openFileToDecrypt reached before the end of the stream) */
        }
        fwrite(bufferOut, 1, (size_t) outputLen, openOutputFile);
    } while (!eof);

    ret = 0;
    ret:
    log_debug("Closing open output file");
    fclose(openOutputFile);
    log_debug("Closing open file to decrypt");
    fclose(openFileToDecrypt);

    //Zero out key in memory
    log_debug("Zeroing crypto key in memory using sodium_memzero() function");
    sodium_memzero(generatedCryptoKey, sizeof(generatedCryptoKey));
    log_info("File decryption finished");

    return ret;
}


void
decrypt_archive();

void
compress_archive();

void
decompress_archive();
