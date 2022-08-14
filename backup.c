#include <assert.h>
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
encrypt_archive(const char *in_file, const char *out_file, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
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

static int
decrypt_archive(const char *fileToDecrypt, const char *outputFile, const unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES])
{
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

    openFileToDecrypt = fopen(fileToDecrypt, "rb");
    openOutputFile = fopen(outputFile, "wb");

    fread(header, 1, sizeof header, openFileToDecrypt);
    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
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
        fclose(openOutputFile);
        fclose(openFileToDecrypt);

    return ret;
}

#define CHUNK 16384

// compress_archive
static int
compress_archive(FILE *source, FILE *dest) 
{
    int ret;
    unsigned have;
    z_stream strm;
    char in[CHUNK];
    char out[CHUNK];
    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK)
        return ret;
    /* decompress until deflate stream ends or end of file */
    do {
        strm.avail_in = fread(in, 1, CHUNK, source);
        if (ferror(source)) {
            (void)inflateEnd(&strm);
            return Z_ERRNO;
        }
        if (strm.avail_in == 0)
            break;
        strm.next_in = in;
        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
            switch (ret) {
            case Z_NEED_DICT:
                ret = Z_DATA_ERROR;     /* and fall through */
            case Z_DATA_ERROR:
            case Z_MEM_ERROR:
                (void)inflateEnd(&strm);
                return ret;
            }
            have = CHUNK - strm.avail_out;
            if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
                (void)inflateEnd(&strm);
                return Z_ERRNO;
            }
        } while (strm.avail_out == 0);
        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);
    /* clean up and return */
    (void)inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

// decompress_archive
// static int
// decompress_archive(FILE *source, FILE *dest)
// {
//     int ret, flush;
//     unsigned have;
//     z_stream strm;
//     char in[CHUNK];
//     char out[CHUNK];
//     /* allocate deflate state */
//     strm.zalloc = Z_NULL;
//     strm.zfree = Z_NULL;
//     strm.opaque = Z_NULL;
//     ret = deflateInit(&strm, level);
//     if (ret != Z_OK)
//         return ret;
//     /* compress until end of file */
//     do {
//         strm.avail_in = fread(in, 1, CHUNK, source);
//         if (ferror(source)) {
//             (void)deflateEnd(&strm);
//             return Z_ERRNO;
//         }
//         flush = feof(source) ? Z_FINISH : Z_NO_FLUSH;
//         strm.next_in = in;
//         /* run deflate() on input until output buffer not full, finish
//            compression if all of source has been read in */
//         do {
//             strm.avail_out = CHUNK;
//             strm.next_out = out;
//             ret = deflate(&strm, flush);    /* no bad return value */
//             assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
//             have = CHUNK - strm.avail_out;
//             if (fwrite(out, 1, have, dest) != have || ferror(dest)) {
//                 (void)deflateEnd(&strm);
//                 return Z_ERRNO;
//             }
//         } while (strm.avail_out == 0);
//         assert(strm.avail_in == 0);     /* all input will be used */
//         /* done when last data in file processed */
//     } while (flush != Z_FINISH);
//     assert(ret == Z_STREAM_END);        /* stream will be complete */
//     /* clean up and return */
//     (void)deflateEnd(&strm);
    
//     return Z_OK;
// }

int
backup_export()
{
    return 0;
}

int
backup_import()
{
    return 0;
}
