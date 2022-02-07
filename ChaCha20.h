/*
 *  This file is part of the ChaCha20 library (https://github.com/marcizhu/ChaCha20)
 *
 *  Copyright (C) 2022 Marc Izquierdo
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 *
 */

/*
 Single file library. #include it as many times as you need, and
 #define CHACHA20_IMPLEMENTATION in *one* c/cpp file BEFORE including it
 */

#ifndef __CHACHA20_H__
#define __CHACHA20_H__

/******************************************************************************
 *                                   HEADER                                   *
 ******************************************************************************/

#include <stdint.h>
#include <stddef.h>

/** @brief Alias for ChaCha20 key type */
typedef uint8_t key256_t[32];

/** @brief Alias for ChaCha20 nonce type */
typedef uint8_t nonce96_t[12];

/** @brief ChaCha20 context */
typedef struct
{
	uint32_t state[4*4];
} ChaCha20_Ctx;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the ChaCha20 Context
 *
 * Initialize the ChaCha20 context with the given 256-bit key, nonce and block
 * count. The block count can be safely set to 0.
 *
 * @param ctx    Pointer to ChaCha20 context
 * @param key    256-bit key
 * @param nonce  96-bit nonce
 * @param count  32-bit block count
 */
void ChaCha20_init(ChaCha20_Ctx* ctx, const key256_t key, const nonce96_t nonce, uint32_t count);

/**
 * @brief XOR a given buffer
 *
 * Encrypts/decrypts a given buffer, automatically incrementing the block count
 * if necessary. It is possible to encript/decrypt a document using multiple
 * calls to this function, but in such case it is required that all but the last
 * call use a buffer length that is integer multiple of 64 bytes (e.g. 256 or
 * 65536 bytes).
 *
 * In ChaCha20, encryption and decryption are the same opperation since it uses
 * an XOR between the given buffer and the key stream. Thus, you can use this
 * function both for encryption and decryption.
 *
 * @pre The context must be initialized prior to this call, and the buffer must
 *      not be @code{c} NULL @endcode.
 *
 * @param ctx      Pointer to ChaCha20 context
 * @param buffer   Pointer to buffer
 * @param bufflen  Length of the buffer
 */
void ChaCha20_xor(ChaCha20_Ctx* ctx, uint8_t* buffer, size_t bufflen);

#ifdef __cplusplus
} // extern "C"
#endif

#ifdef CHACHA20_IMPLEMENTATION
/******************************************************************************
 *                               IMPLEMENTATION                               *
 ******************************************************************************/

#include <assert.h>

#define CHACHA20_CONSTANT       "expand 32-byte k"
#define CHACHA20_ROTL(x, n)     (((x) << (n)) | ((x) >> (32 - (n))))
#define CHACHA20_QR(a, b, c, d)               \
	a += b; d ^= a; d = CHACHA20_ROTL(d, 16); \
	c += d; b ^= c; b = CHACHA20_ROTL(b, 12); \
	a += b; d ^= a; d = CHACHA20_ROTL(d,  8); \
	c += d; b ^= c; b = CHACHA20_ROTL(b,  7)

#ifdef __cplusplus
extern "C" {
#endif

static uint32_t pack4(const uint8_t* a)
{
	uint32_t res =
		  (uint32_t)a[0] << 0 * 8
		| (uint32_t)a[1] << 1 * 8
		| (uint32_t)a[2] << 2 * 8
		| (uint32_t)a[3] << 3 * 8;

	return res;
}

static void ChaCha20_block_next(const uint32_t in[16], uint32_t out[16], uint8_t** keystream)
{
	for(int i = 0; i < 4*4; i++)
		out[i] = in[i];

	// Round 1/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]); // Column 0
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]); // Column 1
	CHACHA20_QR(out[2], out[6], out[10], out[14]); // Column 2
	CHACHA20_QR(out[3], out[7], out[11], out[15]); // Column 3
	CHACHA20_QR(out[0], out[5], out[10], out[15]); // Diagonal 1 (main diagonal)
	CHACHA20_QR(out[1], out[6], out[11], out[12]); // Diagonal 2
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]); // Diagonal 3
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]); // Diagonal 4

	// Round 2/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 3/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 4/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 5/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 6/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 7/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 8/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 9/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	// Round 10/10
	CHACHA20_QR(out[0], out[4], out[ 8], out[12]);
	CHACHA20_QR(out[1], out[5], out[ 9], out[13]);
	CHACHA20_QR(out[2], out[6], out[10], out[14]);
	CHACHA20_QR(out[3], out[7], out[11], out[15]);
	CHACHA20_QR(out[0], out[5], out[10], out[15]);
	CHACHA20_QR(out[1], out[6], out[11], out[12]);
	CHACHA20_QR(out[2], out[7], out[ 8], out[13]);
	CHACHA20_QR(out[3], out[4], out[ 9], out[14]);

	for(int i = 0; i < 4*4; i++)
		out[i] += in[i];

	if(keystream != NULL)
		*keystream = (uint8_t*)out;
}

void ChaCha20_init(ChaCha20_Ctx* ctx, const key256_t key, const nonce96_t nonce, uint32_t count)
{
	ctx->state[ 0] = pack4((const uint8_t*)CHACHA20_CONSTANT + 0 * 4);
	ctx->state[ 1] = pack4((const uint8_t*)CHACHA20_CONSTANT + 1 * 4);
	ctx->state[ 2] = pack4((const uint8_t*)CHACHA20_CONSTANT + 2 * 4);
	ctx->state[ 3] = pack4((const uint8_t*)CHACHA20_CONSTANT + 3 * 4);
	ctx->state[ 4] = pack4(key + 0 * 4);
	ctx->state[ 5] = pack4(key + 1 * 4);
	ctx->state[ 6] = pack4(key + 2 * 4);
	ctx->state[ 7] = pack4(key + 3 * 4);
	ctx->state[ 8] = pack4(key + 4 * 4);
	ctx->state[ 9] = pack4(key + 5 * 4);
	ctx->state[10] = pack4(key + 6 * 4);
	ctx->state[11] = pack4(key + 7 * 4);
	ctx->state[12] = count;
	ctx->state[13] = pack4(nonce + 0 * 4);
	ctx->state[14] = pack4(nonce + 1 * 4);
	ctx->state[15] = pack4(nonce + 2 * 4);
}

void ChaCha20_xor(ChaCha20_Ctx* ctx, uint8_t* buffer, size_t bufflen)
{
	uint32_t tmp[4*4];
	uint8_t* keystream = NULL;

	for(size_t i = 0; i < bufflen; i += 64)
	{
		ChaCha20_block_next(ctx->state, tmp, &keystream);
		ctx->state[12]++;

		if(ctx->state[12] == 0)
		{
			ctx->state[13]++;
			assert(ctx->state[13] != 0);
		}

		for(size_t j = i; j < i + 64; j++)
		{
			if(j >= bufflen)
				break;

			buffer[j] = buffer[j] ^ keystream[j - i];
		}
	}
}

#ifdef __cplusplus
} // extern "C"
#endif

#ifndef CHACHA20_NO_UNDEF
	#undef CHACHA20_CONSTANT
	#undef CHACHA20_ROTL
	#undef CHACHA20_QR
#endif

#endif // CHACHA20_IMPLEMENTATION
#endif // __CHACHA20_H__
