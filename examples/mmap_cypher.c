#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"

// Memory-map a file, encrypt/decrypt it in place and sync it back to disk.
// Running this program twice on the same file yields the original one

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		fprintf(stderr, "usage: %s <file>\n", argv[0]);
		return EXIT_FAILURE;
	}

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

	int fd = open(argv[1], O_RDWR);
	if (fd == -1)
	{
		perror(argv[1]);
		return EXIT_FAILURE;
	}

	struct stat st;
	if (fstat(fd, &st) == -1)
	{
		perror(argv[1]);
		close(fd);
		return EXIT_FAILURE;
	}

	if (st.st_size == 0)
	{
		close(fd);
		return EXIT_SUCCESS;
	}

	void* map = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
	{
		perror(argv[1]);
		close(fd);
		return EXIT_FAILURE;
	}

	ChaCha20_Ctx ctx;
	ChaCha20_init(&ctx, key, nonce, count);
	ChaCha20_xor(&ctx, (uint8_t*)map, (size_t)st.st_size);
	ChaCha20_clear(&ctx);

	if (msync(map, (size_t)st.st_size, MS_SYNC) != 0)
	{
		perror(argv[1]);
		munmap(map, (size_t)st.st_size);
		close(fd);
		return EXIT_FAILURE;
	}

	munmap(map, (size_t)st.st_size);
	close(fd);
	return EXIT_SUCCESS;
}
