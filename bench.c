#include <math.h>
#include <stdio.h>
#include <sys/time.h>

#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

static key256_t key = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static nonce96_t nonce = {
	0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
	0x00, 0x00, 0x00, 0x00,
};

static double gettimedouble(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_usec * 0.000001 + tv.tv_sec;
}

static void run_benchmark(char* name, void (*benchmark)(void*), void* data, int count, int iter)
{
	double min = +HUGE_VAL;
	double max = -HUGE_VAL;
	double sum = 0.0;

	for(int i = 0; i < count; i++)
	{
		double begin = gettimedouble();
		benchmark(data);
		double total = gettimedouble() - begin;

		min = MIN(min, total);
		max = MAX(max, total);
		sum += total;
	}

	min *= 1.0e9 / iter;
	max *= 1.0e9 / iter;
	sum *= 1.0e9 / iter;

	printf("\x1b[1m%s\x1b[0m: min %4.2fns / avg %4.2fns / max %4.2fns\n", name, min, sum / count, max);
}

static void bench_chacha_init(void* data)
{
    ChaCha20_Ctx* ctx = (ChaCha20_Ctx*)data;

    for(int i = 0; i < 50000; i++)
        ChaCha20_init(ctx, key, nonce, 0);
}

static void bench_chacha_encrypt_16(void* data)
{
	ChaCha20_Ctx* ctx = (ChaCha20_Ctx*)data;
	uint8_t scratch[16] = {0};

	for(int i = 0; i < 4000000 / 16; i++)
		ChaCha20_xor(ctx, scratch, 16);
}

static void bench_chacha_encrypt_64(void* data)
{
	ChaCha20_Ctx* ctx = (ChaCha20_Ctx*)data;
	uint8_t scratch[64] = {0};

	for(int i = 0; i < 4000000 / 64; i++)
		ChaCha20_xor(ctx, scratch, 64);
}

static void bench_chacha_encrypt_256(void* data)
{
	ChaCha20_Ctx* ctx = (ChaCha20_Ctx*)data;
	uint8_t scratch[256] = {0};

	for(int i = 0; i < 4000000 / 256; i++)
		ChaCha20_xor(ctx, scratch, 256);
}

int main()
{
	ChaCha20_Ctx ctx;

	// ChaCha20 Initialization
	run_benchmark("ChaCha20: Initialization", bench_chacha_init, &ctx, 50, 50000);

	// ChaCha20 Encryption/Decryption
	run_benchmark("ChaCha20: Encryption (16-byte blocks)",  bench_chacha_encrypt_16,  &ctx, 50, 4000000);
	run_benchmark("ChaCha20: Encryption (64-byte blocks)",  bench_chacha_encrypt_64,  &ctx, 50, 4000000);
	run_benchmark("ChaCha20: Encryption (256-byte blocks)", bench_chacha_encrypt_256, &ctx, 50, 4000000);
	return 0;
}
