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
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */
#ifndef _SCRYPTENC_H_
#define _SCRYPTENC_H_

#include <stdint.h>
#include <stdio.h>

/**
 * NOTE: This file provides prototypes for routines which encrypt/decrypt data
 * using a key derived from a password by using the scrypt key derivation
 * function.  If you are just trying to "hash" a password for user logins,
 * this is not the code you are looking for.  You want to use the crypto_scrypt
 * function directly.
 */
/**
 * Return codes from scrypt(enc|dec)_(buf|file):
 * 0	success
 * 1	getrlimit or sysctl(hw.usermem) failed
 * 2	clock_getres or clock_gettime failed
 * 3	error computing derived key
 * 4	could not read salt from /dev/urandom
 * 5	error in OpenSSL
 * 6	malloc failed
 * 7	data is not a valid scrypt-encrypted block
 * 8	unrecognized scrypt format
 * 9	decrypting file would take too much memory
 * 10	decrypting file would take too long
 * 11	password is incorrect
 * 12	error writing output file
 * 13	error reading input file
 */

/**
 * scryptenc_buf(inbuf, inbuflen, outbuf, passwd, passwdlen,
 *     salt, rounds, memcost):
 * Encrypt inbuflen bytes from inbuf, writing the resulting inbuflen
 * bytes to outbuf. Salt length must be 32.
 */
int scryptenc_buf(const uint8_t *, size_t, uint8_t *,
    const uint8_t *, size_t, const uint8_t *, uint32_t, uint32_t);

/*
 * scryptenc_buf_saltlen(inbuf, inbuflen, outbuf, passwd, passwdlen,
 *     salt, rounds, memcost):
 * Encrypt inbuflen bytes from inbuf, writing the resulting inbuflen
 * bytes to outbuf. Salt length is variable.
 */
int scryptenc_buf_saltlen(const uint8_t *, size_t, uint8_t *,
    const uint8_t *, size_t, const uint8_t *, size_t, uint32_t, uint32_t);

/**
 * scryptdec_buf(inbuf, inbuflen, outbuf, passwd, passwdlen,
 *     salt, rounds, memcost):
 * Decrypt inbuflen bytes from inbuf, writing the result into outbuf and the
 * decrypted data length to outlen.  The allocated length of outbuf must
 * be at least inbuflen. Salt length must be 32.
 */
int scryptdec_buf(const uint8_t *, size_t, uint8_t *, const uint8_t *,
                  size_t, const uint8_t *, uint32_t, uint32_t);

/*
 * scryptdec_buf_saltlen(inbuf, inbuflen, outbuf, passwd, passwdlen,
 *     salt, rounds, memcost):
 * Decrypt inbuflen bytes from inbuf, writing the result into outbuf and the
 * decrypted data length to outlen.  The allocated length of outbuf must
 * be at least inbuflen. Salt length is variable.
 */
int scryptdec_buf_saltlen(const uint8_t *, size_t, uint8_t *, const uint8_t *,
                  size_t, const uint8_t *, size_t, uint32_t, uint32_t);

#endif /* !_SCRYPTENC_H_ */
