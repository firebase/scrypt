/*-
 * Copyright 2009 Colin Percival
 * Copyright 2018 Google LLC
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "scrypt_platform.h"

#include <alloca.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include "getopt.h"
#include "humansize.h"
#include "insecure_memzero.h"
#include "readpass.h"
#include "scryptenc.h"
#include "warnp.h"

void
usage()
{
    fprintf(stderr, "usage: scrypt {key} {salt base} {salt separator} {rounds} {memcost} [-P]\n");
    exit(1);
}

int
decodeBase64(char* input, char** output) {
    BIO *bio, *b64;

    size_t inlen = strlen(input);
    *output = malloc(inlen + 1);
    (*output)[inlen] = '\0';

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input, -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    size_t outlen = BIO_read(bio, *output, strlen(input));
    BIO_free_all(bio);

    return outlen;
}

size_t
encodeBase64(const unsigned char* input, size_t inlen, char** output) {
    BIO *bio, *b64;
    BUF_MEM *bioMemPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input, inlen);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bioMemPtr);
    BIO_set_close(bio, BIO_NOCLOSE);

    size_t outlen = bioMemPtr->length;
    *output = malloc(outlen);
    memcpy(*output, bioMemPtr->data, outlen);

    BIO_free_all(bio);
    return outlen;
}

int
main(int argc, char *argv[])
{
    int devtty = 1;

    WARNP_INIT;

    if (argc < 5) {
        usage();
    }

    char   * key,  * salt,  * saltbase,  * saltsep;
    size_t keylen, saltlen, saltbaselen, saltseplen;
    int rounds;
    int memcost;

    keylen = decodeBase64(argv[1], &key);
    saltbaselen = decodeBase64(argv[2], &saltbase);
    saltseplen = decodeBase64(argv[3], &saltsep);
    rounds = atoi(argv[4]);
    memcost = atoi(argv[5]);
    argc-=5;
    argv+=5;

    /* Parse arguments. */
    const char * ch;
    while ((ch = GETOPT(argc, argv)) != NULL) {
        GETOPT_SWITCH(ch) {
        GETOPT_OPT("-P"):
            devtty = 0;
            break;
        GETOPT_MISSING_ARG:
            warn0("Missing argument to %s\n", ch);
            usage();
        GETOPT_DEFAULT:
            warn0("illegal option -- %s\n", ch);
            usage();
        }
    }
    argc -= optind;
    argv += optind;
    if (argc) {
        usage();
    }

    /* Prompt for a password. */
    char * passwd;
    if (readpass(&passwd, "Please enter passphrase",
                 !devtty ? NULL : "Please confirm passphrase", devtty)) {
        exit(1);
    }

    /* Prepare the salt */
    saltlen = saltbaselen + saltseplen;
    salt = malloc(saltlen);
    memcpy(salt, saltbase, saltbaselen);
    memcpy(salt + saltbaselen, saltsep, saltseplen);

    /* Alloc a response buffer */
    void * outbuf = alloca(keylen);

    /* Hash the given parameters and put the output in the response buffer. */
    int rc = scryptenc_buf_saltlen((uint8_t *) key, keylen,
                                  (uint8_t *) outbuf,
                                  (uint8_t *) passwd, strlen(passwd),
                                  (uint8_t *) salt, saltlen,
                                  rounds, memcost);

    /* Zero and free the password. */
    insecure_memzero(passwd, strlen(passwd));
    free(passwd);

    /* Free everything else */
    free(key);
    free(salt);
    free(saltbase);
    free(saltsep);

    /* Print the response buffer if the scrypt hash was successful. */
    if (rc == 0) {
        char* be64out;
        size_t be64outlen = encodeBase64(outbuf, keylen, &be64out);
        if(!fwrite(be64out, 1, be64outlen, stdout) == be64outlen) {
            perror("fwrite");
        }
        free(be64out);
        return (0);
    } else {
        /* If we failed, print the right error message and exit. */
        switch (rc) {
        case 1:
            warnp("Error determining amount of available memory");
            break;
        case 2:
            warnp("Error reading clocks");
            break;
        case 3:
            warnp("Error computing derived key");
            break;
        case 4:
            warnp("Error reading salt");
            break;
        case 5:
            warnp("OpenSSL error");
            break;
        case 6:
            warnp("Error allocating memory");
            break;
        case 7:
            warn0("Input is not valid scrypt-encrypted block");
            break;
        case 8:
            warn0("Unrecognized scrypt format version");
            break;
        case 9:
            warn0("Decrypting file would require too much memory");
            break;
        case 10:
            warn0("Decrypting file would take too much CPU time");
            break;
        case 11:
            warn0("Passphrase is incorrect");
            break;
        }
      exit(1);
    }
}
