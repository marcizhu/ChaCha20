#include <stdio.h>
#include <stdlib.h>

#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"

// Read file in 64 KiB chunks. Chunk size can be anything, but multiples of 64 are faster
#define CHUNK_SIZE 64 * 1024

int main(void)
{
	// This example loads data in chunks, encrypts/decrypts it and writes
	// it to stdout. You can redirect the output to a file in order to save
	// it, and running this program on this new file should yield the original
	// one

	key256_t key = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};

	nonce96_t nonce = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00
	};

	uint32_t count = 0x00000000;

	ChaCha20_Ctx ctx;
	ChaCha20_init(&ctx, key, nonce, count);

	uint8_t buff[CHUNK_SIZE] = { 0, };

	for(;;)
	{
		int n = fread(buff, sizeof(uint8_t), CHUNK_SIZE, stdin);
		if (n <= 0 && feof(stdin))
			break;

		ChaCha20_xor(&ctx, buff, n);
		fwrite(buff, 1, n, stdout);
	}
}
