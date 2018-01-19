/*
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

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_aes.h"
#include "crypto_aesctr.h"
#include "crypto_entropy.h"
#include "humansize.h"
#include "insecure_memzero.h"
#include "sha256.h"
#include "sysendian.h"

#include "crypto_scrypt.h"

#include "scryptenc.h"

#define ENCBLOCK 65536

static void
display_params(int logN, uint32_t r, uint32_t p, size_t memlimit,
	double opps, double maxtime)
{
	uint64_t N = (uint64_t)(1) << logN;
	uint64_t mem_minimum = 128 * r * N;
	double expected_seconds = 4 * N * p / opps;
	char * human_memlimit = humansize(memlimit);
	char * human_mem_minimum = humansize(mem_minimum);

	fprintf(stderr, "Parameters used: N = %" PRIu64 "; r = %" PRIu32
		"; p = %" PRIu32 ";\n", N, r, p);
	fprintf(stderr, "    This requires at least %s bytes of memory "
		"(%s available),\n", human_mem_minimum, human_memlimit);
	fprintf(stderr, "    and will take approximately %.1f seconds "
		"(limit: %.1f seconds).\n", expected_seconds, maxtime);

	free(human_memlimit);
	free(human_mem_minimum);
}

/**
 * scryptenc_buf(inbuf, inbuflen, outbuf, passwd, passwdlen, salt, rounds,
 * memcost):
 * Encrypt inbuflen bytes from inbuf, writing the resulting inbuflen
 * bytes to outbuf. Salt length must be 32.
 */
extern  int scryptenc_buf(const uint8_t * inbuf, size_t inbuflen,
						  uint8_t * outbuf, const uint8_t * passwd,
						  size_t passwdlen, const uint8_t* salt,
						  uint32_t rounds, uint32_t memcost)
{
  return scryptenc_buf_saltlen(inbuf, inbuflen, outbuf, passwd, passwdlen, salt,
							   32, rounds, memcost);
}

/**
 * scryptenc_buf_saltlen(inbuf, inbuflen, outbuf, passwd, passwdlen, salt,
 * saltlen, rounds, memcost):
 * Encrypt inbuflen bytes from inbuf, writing the resulting inbuflen
 * bytes to outbuf.
 */
extern  int scryptenc_buf_saltlen(const uint8_t * inbuf, size_t inbuflen,
						  uint8_t * outbuf, const uint8_t * passwd,
						  size_t passwdlen, const uint8_t* salt, size_t saltlen,
						  uint32_t rounds, uint32_t memcost)
{
  uint8_t dk[64];
  uint8_t * key_enc = dk;
  int rc;
  struct crypto_aes_key * key_enc_exp;
  struct crypto_aesctr * AES;

  uint32_t p = 1;
  uint64_t N = (uint64_t)(1) << memcost;
  if ((rc = crypto_scrypt(passwd, passwdlen, salt, saltlen, N, rounds, p, dk,
						  64)) != 0)
	return rc;

	/* Encrypt data. */
	if ((key_enc_exp = crypto_aes_key_expand(key_enc, 32)) == NULL)
		return (5);
	if ((AES = crypto_aesctr_init(key_enc_exp, 0)) == NULL)
		return (6);
	crypto_aesctr_stream(AES, inbuf, &outbuf[0], inbuflen);
	crypto_aesctr_free(AES);
	crypto_aes_key_free(key_enc_exp);

	/* Zero sensitive data. */
	insecure_memzero(dk, 64);

	/* Success! */
	return (0);
}

/**
 * scryptdec_buf(inbuf, inbuflen, outbuf, passwd, passwdlen, salt,
 * rounds, memcost):
 * Decrypt inbuflen bytes fro inbuf, writing the result into outbuf and the
 * decrypted data length to outlen.  The allocated length of outbuf must
 * be at least inbuflen. Salt length must be 32.
 */
int scryptdec_buf(const uint8_t * inbuf, size_t inbuflen, uint8_t * outbuf,
				  const uint8_t * passwd, size_t passwdlen,
				  const uint8_t * salt, uint32_t rounds, uint32_t memcost)
{
  return scryptdec_buf_saltlen(inbuf, inbuflen, outbuf, passwd, passwdlen,
							   salt, 32, rounds, memcost);
}

/**
 * scryptdec_buf_saltlen(inbuf, inbuflen, outbuf, passwd, passwdlen, salt,
 * rounds, memcost):
 * Decrypt inbuflen bytes fro inbuf, writing the result into outbuf and the
 * decrypted data length to outlen.  The allocated length of outbuf must
 * be at least inbuflen.
 */
  int scryptdec_buf_saltlen(const uint8_t * inbuf, size_t inbuflen,
							uint8_t * outbuf, const uint8_t * passwd,
							size_t passwdlen, const uint8_t * salt,
							size_t saltlen, uint32_t rounds, uint32_t memcost)
{
  uint8_t dk[64];
  uint8_t * key_enc = dk;
  int rc;
  struct crypto_aes_key * key_enc_exp;
  struct crypto_aesctr * AES;

  uint32_t p = 1;
  uint64_t N = (uint64_t)(1) << memcost;
  if ((rc = crypto_scrypt(passwd, passwdlen, salt, saltlen, N, rounds, p, dk, 64)) != 0)
	return rc;

  /* Decrypt data. */
	if ((key_enc_exp = crypto_aes_key_expand(key_enc, 32)) == NULL)
		return (5);
	if ((AES = crypto_aesctr_init(key_enc_exp, 0)) == NULL)
		return (6);
	crypto_aesctr_stream(AES, &inbuf[0], outbuf, inbuflen);
	crypto_aesctr_free(AES);
	crypto_aes_key_free(key_enc_exp);

	/* Zero sensitive data. */
	insecure_memzero(dk, 64);

	/* Success! */
	return (0);
}
