#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define CHACHA20_IMPLEMENTATION
#define CHACHA20_NO_UNDEF
#include "ChaCha20.h"

#define suite(...) if(tst>0&&prev==err)printf("\r \x1b[32m✓\x1b[0m \n");if(printf("   \x1b[1m" __VA_ARGS__ "\x1b[0m"),prev=err,(once=0),1)
#define test(...)  do{(++tst,err+=!(ok=!!(__VA_ARGS__)));if(!ok){if(!once){printf("\r \x1b[31m✗\x1b[0m \n");once=1;}printf("   \x1b[31m✗\x1b[0m %s:%d → %s\n",__FILE__,__LINE__,#__VA_ARGS__);}}while(0)
static unsigned tst=0,err=0,ok=1,prev=0,once=0;
static void summary(void){if(tst>0&&prev==err)printf("\r \x1b[32m✓\x1b[0m \n");printf("\r  \n\x1b[1m\x1b[33m    %d total", tst);printf("\x1b[1m\x1b[32m   %d passed",tst-err);printf("\x1b[1m\x1b[31m   %d failed\x1b\x1b[0m\n",err);exit(err);}

int main()
{
	atexit(summary);

	suite("ChaCha20 Quarter Round Test Vector")
	{
		uint32_t state[4*4] = {
			0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
			0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
			0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
			0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320,
		};

		uint32_t expected[4*4] = {
			0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
			0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
			0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
			0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320,
		};

		CHACHA20_QR(state[2], state[7], state[8], state[13]);

		for(int i = 0; i < 4*4; i++)
			test(state[i] == expected[i]);
	}

	suite("ChaCha20 Block Function Test Vector #0")
	{
		key256_t key = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
			0x00, 0x00, 0x00, 0x00,
		};

		uint32_t count = 0x00000001;

		uint32_t expected_state[4*4] = {
			0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
			0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
			0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
			0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
		};

		uint8_t expected_keystream[] = {
			0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
			0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
			0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
			0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
			0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
			0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
			0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
			0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
		};

		uint32_t state[4*4];
		uint8_t* keystream = NULL;

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_block_next(ctx.state, state, &keystream);

		for(int i = 0; i < 4*4; i++)
			test(state[i] == expected_state[i]);

		for(int i = 0; i < 64; i++)
			test(keystream[i] == expected_keystream[i]);
	}

	suite("ChaCha20 Block Function Test Vector #1")
	{
		key256_t key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		uint32_t count = 0x00000000;

		uint32_t expected_state[4*4] = {
			0xade0b876, 0x903df1a0, 0xe56a5d40, 0x28bd8653,
			0xb819d2bd, 0x1aed8da0, 0xccef36a8, 0xc70d778b,
			0x7c5941da, 0x8d485751, 0x3fe02477, 0x374ad8b8,
			0xf4b8436a, 0x1ca11815, 0x69b687c3, 0x8665eeb2,
		};

		uint8_t expected_keystream[] = {
			0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
			0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
			0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
			0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
			0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
			0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
			0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
			0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
		};

		uint32_t state[4*4];
		uint8_t* keystream = NULL;

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_block_next(ctx.state, state, &keystream);

		for(int i = 0; i < 4*4; i++)
			test(state[i] == expected_state[i]);

		for(int i = 0; i < 64; i++)
			test(keystream[i] == expected_keystream[i]);
	}

	suite("ChaCha20 Block Function Test Vector #2")
	{
		key256_t key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		uint32_t count = 0x00000001;

		uint32_t expected_state[4*4] = {
			0xbee7079f, 0x7a385155, 0x7c97ba98, 0x0d082d73,
			0xa0290fcb, 0x6965e348, 0x3e53c612, 0xed7aee32,
			0x7621b729, 0x434ee69c, 0xb03371d5, 0xd539d874,
			0x281fed31, 0x45fb0a51, 0x1f0ae1ac, 0x6f4d794b,
		};

		uint8_t expected_keystream[] = {
			0x9f, 0x07, 0xe7, 0xbe, 0x55, 0x51, 0x38, 0x7a,
			0x98, 0xba, 0x97, 0x7c, 0x73, 0x2d, 0x08, 0x0d,
			0xcb, 0x0f, 0x29, 0xa0, 0x48, 0xe3, 0x65, 0x69,
			0x12, 0xc6, 0x53, 0x3e, 0x32, 0xee, 0x7a, 0xed,
			0x29, 0xb7, 0x21, 0x76, 0x9c, 0xe6, 0x4e, 0x43,
			0xd5, 0x71, 0x33, 0xb0, 0x74, 0xd8, 0x39, 0xd5,
			0x31, 0xed, 0x1f, 0x28, 0x51, 0x0a, 0xfb, 0x45,
			0xac, 0xe1, 0x0a, 0x1f, 0x4b, 0x79, 0x4d, 0x6f,
		};

		uint32_t state[4*4];
		uint8_t* keystream = NULL;

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_block_next(ctx.state, state, &keystream);

		for(int i = 0; i < 4*4; i++)
			test(state[i] == expected_state[i]);

		for(int i = 0; i < 64; i++)
			test(keystream[i] == expected_keystream[i]);
	}

	suite("ChaCha20 Block Function Test Vector #3")
	{
		key256_t key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		uint32_t count = 0x00000001;

		uint32_t expected_state[4*4] = {
			0x2452eb3a, 0x9249f8ec, 0x8d829d9b, 0xddd4ceb1,
			0xe8252083, 0x60818b01, 0xf38422b8, 0x5aaa49c9,
			0xbb00ca8e, 0xda3ba7b4, 0xc4b592d1, 0xfdf2732f,
			0x4436274e, 0x2561b3c8, 0xebdd4aa6, 0xa0136c00,
		};

		uint8_t expected_keystream[] = {
			0x3a, 0xeb, 0x52, 0x24, 0xec, 0xf8, 0x49, 0x92,
			0x9b, 0x9d, 0x82, 0x8d, 0xb1, 0xce, 0xd4, 0xdd,
			0x83, 0x20, 0x25, 0xe8, 0x01, 0x8b, 0x81, 0x60,
			0xb8, 0x22, 0x84, 0xf3, 0xc9, 0x49, 0xaa, 0x5a,
			0x8e, 0xca, 0x00, 0xbb, 0xb4, 0xa7, 0x3b, 0xda,
			0xd1, 0x92, 0xb5, 0xc4, 0x2f, 0x73, 0xf2, 0xfd,
			0x4e, 0x27, 0x36, 0x44, 0xc8, 0xb3, 0x61, 0x25,
			0xa6, 0x4a, 0xdd, 0xeb, 0x00, 0x6c, 0x13, 0xa0,
		};

		uint32_t state[4*4];
		uint8_t* keystream = NULL;

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_block_next(ctx.state, state, &keystream);

		for(int i = 0; i < 4*4; i++)
			test(state[i] == expected_state[i]);

		for(int i = 0; i < 64; i++)
			test(keystream[i] == expected_keystream[i]);
	}

	suite("ChaCha20 Block Function Test Vector #4")
	{
		key256_t key = {
			0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		uint32_t count = 0x00000002;

		uint32_t expected_state[4*4] = {
			0xfb4dd572, 0x4bc42ef1, 0xdf922636, 0x327f1394,
			0xa78dea8f, 0x5e269039, 0xa1bebbc1, 0xcaf09aae,
			0xa25ab213, 0x48a6b46c, 0x1b9d9bcb, 0x092c5be6,
			0x546ca624, 0x1bec45d5, 0x87f47473, 0x96f0992e,
		};

		uint8_t expected_keystream[] = {
			0x72, 0xd5, 0x4d, 0xfb, 0xf1, 0x2e, 0xc4, 0x4b,
			0x36, 0x26, 0x92, 0xdf, 0x94, 0x13, 0x7f, 0x32,
			0x8f, 0xea, 0x8d, 0xa7, 0x39, 0x90, 0x26, 0x5e,
			0xc1, 0xbb, 0xbe, 0xa1, 0xae, 0x9a, 0xf0, 0xca,
			0x13, 0xb2, 0x5a, 0xa2, 0x6c, 0xb4, 0xa6, 0x48,
			0xcb, 0x9b, 0x9d, 0x1b, 0xe6, 0x5b, 0x2c, 0x09,
			0x24, 0xa6, 0x6c, 0x54, 0xd5, 0x45, 0xec, 0x1b,
			0x73, 0x74, 0xf4, 0x87, 0x2e, 0x99, 0xf0, 0x96,
		};

		uint32_t state[4*4];
		uint8_t* keystream = NULL;

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_block_next(ctx.state, state, &keystream);

		for(int i = 0; i < 4*4; i++)
			test(state[i] == expected_state[i]);

		for(int i = 0; i < 64; i++)
			test(keystream[i] == expected_keystream[i]);
	}

	suite("ChaCha20 Block Function Test Vector #5")
	{
		key256_t key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x02,
		};

		uint32_t count = 0x00000000;

		uint32_t expected_state[4*4] = {
			0x374dc6c2, 0x3736d58c, 0xb904e24a, 0xcd3f93ef,
			0x88228b1a, 0x96a4dfb3, 0x5b76ab72, 0xc727ee54,
			0x0e0e978a, 0xf3145c95, 0x1b748ea8, 0xf786c297,
			0x99c28f5f, 0x628314e8, 0x398a19fa, 0x6ded1b53,
		};

		uint8_t expected_keystream[] = {
			0xc2, 0xc6, 0x4d, 0x37, 0x8c, 0xd5, 0x36, 0x37,
			0x4a, 0xe2, 0x04, 0xb9, 0xef, 0x93, 0x3f, 0xcd,
			0x1a, 0x8b, 0x22, 0x88, 0xb3, 0xdf, 0xa4, 0x96,
			0x72, 0xab, 0x76, 0x5b, 0x54, 0xee, 0x27, 0xc7,
			0x8a, 0x97, 0x0e, 0x0e, 0x95, 0x5c, 0x14, 0xf3,
			0xa8, 0x8e, 0x74, 0x1b, 0x97, 0xc2, 0x86, 0xf7,
			0x5f, 0x8f, 0xc2, 0x99, 0xe8, 0x14, 0x83, 0x62,
			0xfa, 0x19, 0x8a, 0x39, 0x53, 0x1b, 0xed, 0x6d,
		};

		uint32_t state[4*4];
		uint8_t* keystream = NULL;

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_block_next(ctx.state, state, &keystream);

		for(int i = 0; i < 4*4; i++)
			test(state[i] == expected_state[i]);

		for(int i = 0; i < 64; i++)
			test(keystream[i] == expected_keystream[i]);
	}

	suite("ChaCha20 Cipher Test Vector #0")
	{
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

		uint32_t count = 0x00000001;

		uint8_t data[] = {
			0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
			0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
			0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20,
			0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
			0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39,
			0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
			0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66,
			0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
			0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20,
			0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
			0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75,
			0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
			0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f,
			0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
			0x74, 0x2e,
		};

		uint8_t ciphertext[] = {
			0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80,
			0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
			0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2,
			0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
			0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab,
			0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
			0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab,
			0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
			0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61,
			0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
			0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06,
			0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
			0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6,
			0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
			0x87, 0x4d,
		};

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_xor(&ctx, data, 114);

		for(int i = 0; i < 114; i++)
			test(data[i] == ciphertext[i]);
	}

	suite("ChaCha20 Cipher Test Vector #1")
	{
		key256_t key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		};

		uint32_t count = 0x00000000;

		uint8_t data[] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		};

		uint8_t ciphertext[] = {
			0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90,
			0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86, 0xbd, 0x28,
			0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a,
			0xa8, 0x36, 0xef, 0xcc, 0x8b, 0x77, 0x0d, 0xc7,
			0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
			0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
			0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
			0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
		};

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_xor(&ctx, data, 64);

		for(int i = 0; i < 64; i++)
			test(data[i] == ciphertext[i]);
	}

	suite("ChaCha20 Cipher Test Vector #2")
	{
		key256_t key = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x02,
		};

		uint32_t count = 0x00000001;

		uint8_t data[] = {
			0x41, 0x6e, 0x79, 0x20, 0x73, 0x75, 0x62, 0x6d,
			0x69, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x20, 0x74,
			0x6f, 0x20, 0x74, 0x68, 0x65, 0x20, 0x49, 0x45,
			0x54, 0x46, 0x20, 0x69, 0x6e, 0x74, 0x65, 0x6e,
			0x64, 0x65, 0x64, 0x20, 0x62, 0x79, 0x20, 0x74,
			0x68, 0x65, 0x20, 0x43, 0x6f, 0x6e, 0x74, 0x72,
			0x69, 0x62, 0x75, 0x74, 0x6f, 0x72, 0x20, 0x66,
			0x6f, 0x72, 0x20, 0x70, 0x75, 0x62, 0x6c, 0x69,
			0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x61,
			0x73, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x6f, 0x72,
			0x20, 0x70, 0x61, 0x72, 0x74, 0x20, 0x6f, 0x66,
			0x20, 0x61, 0x6e, 0x20, 0x49, 0x45, 0x54, 0x46,
			0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65,
			0x74, 0x2d, 0x44, 0x72, 0x61, 0x66, 0x74, 0x20,
			0x6f, 0x72, 0x20, 0x52, 0x46, 0x43, 0x20, 0x61,
			0x6e, 0x64, 0x20, 0x61, 0x6e, 0x79, 0x20, 0x73,
			0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e, 0x74,
			0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x77, 0x69,
			0x74, 0x68, 0x69, 0x6e, 0x20, 0x74, 0x68, 0x65,
			0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74,
			0x20, 0x6f, 0x66, 0x20, 0x61, 0x6e, 0x20, 0x49,
			0x45, 0x54, 0x46, 0x20, 0x61, 0x63, 0x74, 0x69,
			0x76, 0x69, 0x74, 0x79, 0x20, 0x69, 0x73, 0x20,
			0x63, 0x6f, 0x6e, 0x73, 0x69, 0x64, 0x65, 0x72,
			0x65, 0x64, 0x20, 0x61, 0x6e, 0x20, 0x22, 0x49,
			0x45, 0x54, 0x46, 0x20, 0x43, 0x6f, 0x6e, 0x74,
			0x72, 0x69, 0x62, 0x75, 0x74, 0x69, 0x6f, 0x6e,
			0x22, 0x2e, 0x20, 0x53, 0x75, 0x63, 0x68, 0x20,
			0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
			0x74, 0x73, 0x20, 0x69, 0x6e, 0x63, 0x6c, 0x75,
			0x64, 0x65, 0x20, 0x6f, 0x72, 0x61, 0x6c, 0x20,
			0x73, 0x74, 0x61, 0x74, 0x65, 0x6d, 0x65, 0x6e,
			0x74, 0x73, 0x20, 0x69, 0x6e, 0x20, 0x49, 0x45,
			0x54, 0x46, 0x20, 0x73, 0x65, 0x73, 0x73, 0x69,
			0x6f, 0x6e, 0x73, 0x2c, 0x20, 0x61, 0x73, 0x20,
			0x77, 0x65, 0x6c, 0x6c, 0x20, 0x61, 0x73, 0x20,
			0x77, 0x72, 0x69, 0x74, 0x74, 0x65, 0x6e, 0x20,
			0x61, 0x6e, 0x64, 0x20, 0x65, 0x6c, 0x65, 0x63,
			0x74, 0x72, 0x6f, 0x6e, 0x69, 0x63, 0x20, 0x63,
			0x6f, 0x6d, 0x6d, 0x75, 0x6e, 0x69, 0x63, 0x61,
			0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x6d, 0x61,
			0x64, 0x65, 0x20, 0x61, 0x74, 0x20, 0x61, 0x6e,
			0x79, 0x20, 0x74, 0x69, 0x6d, 0x65, 0x20, 0x6f,
			0x72, 0x20, 0x70, 0x6c, 0x61, 0x63, 0x65, 0x2c,
			0x20, 0x77, 0x68, 0x69, 0x63, 0x68, 0x20, 0x61,
			0x72, 0x65, 0x20, 0x61, 0x64, 0x64, 0x72, 0x65,
			0x73, 0x73, 0x65, 0x64, 0x20, 0x74, 0x6f,
		};

		uint8_t ciphertext[] = {
			0xa3, 0xfb, 0xf0, 0x7d, 0xf3, 0xfa, 0x2f, 0xde,
			0x4f, 0x37, 0x6c, 0xa2, 0x3e, 0x82, 0x73, 0x70,
			0x41, 0x60, 0x5d, 0x9f, 0x4f, 0x4f, 0x57, 0xbd,
			0x8c, 0xff, 0x2c, 0x1d, 0x4b, 0x79, 0x55, 0xec,
			0x2a, 0x97, 0x94, 0x8b, 0xd3, 0x72, 0x29, 0x15,
			0xc8, 0xf3, 0xd3, 0x37, 0xf7, 0xd3, 0x70, 0x05,
			0x0e, 0x9e, 0x96, 0xd6, 0x47, 0xb7, 0xc3, 0x9f,
			0x56, 0xe0, 0x31, 0xca, 0x5e, 0xb6, 0x25, 0x0d,
			0x40, 0x42, 0xe0, 0x27, 0x85, 0xec, 0xec, 0xfa,
			0x4b, 0x4b, 0xb5, 0xe8, 0xea, 0xd0, 0x44, 0x0e,
			0x20, 0xb6, 0xe8, 0xdb, 0x09, 0xd8, 0x81, 0xa7,
			0xc6, 0x13, 0x2f, 0x42, 0x0e, 0x52, 0x79, 0x50,
			0x42, 0xbd, 0xfa, 0x77, 0x73, 0xd8, 0xa9, 0x05,
			0x14, 0x47, 0xb3, 0x29, 0x1c, 0xe1, 0x41, 0x1c,
			0x68, 0x04, 0x65, 0x55, 0x2a, 0xa6, 0xc4, 0x05,
			0xb7, 0x76, 0x4d, 0x5e, 0x87, 0xbe, 0xa8, 0x5a,
			0xd0, 0x0f, 0x84, 0x49, 0xed, 0x8f, 0x72, 0xd0,
			0xd6, 0x62, 0xab, 0x05, 0x26, 0x91, 0xca, 0x66,
			0x42, 0x4b, 0xc8, 0x6d, 0x2d, 0xf8, 0x0e, 0xa4,
			0x1f, 0x43, 0xab, 0xf9, 0x37, 0xd3, 0x25, 0x9d,
			0xc4, 0xb2, 0xd0, 0xdf, 0xb4, 0x8a, 0x6c, 0x91,
			0x39, 0xdd, 0xd7, 0xf7, 0x69, 0x66, 0xe9, 0x28,
			0xe6, 0x35, 0x55, 0x3b, 0xa7, 0x6c, 0x5c, 0x87,
			0x9d, 0x7b, 0x35, 0xd4, 0x9e, 0xb2, 0xe6, 0x2b,
			0x08, 0x71, 0xcd, 0xac, 0x63, 0x89, 0x39, 0xe2,
			0x5e, 0x8a, 0x1e, 0x0e, 0xf9, 0xd5, 0x28, 0x0f,
			0xa8, 0xca, 0x32, 0x8b, 0x35, 0x1c, 0x3c, 0x76,
			0x59, 0x89, 0xcb, 0xcf, 0x3d, 0xaa, 0x8b, 0x6c,
			0xcc, 0x3a, 0xaf, 0x9f, 0x39, 0x79, 0xc9, 0x2b,
			0x37, 0x20, 0xfc, 0x88, 0xdc, 0x95, 0xed, 0x84,
			0xa1, 0xbe, 0x05, 0x9c, 0x64, 0x99, 0xb9, 0xfd,
			0xa2, 0x36, 0xe7, 0xe8, 0x18, 0xb0, 0x4b, 0x0b,
			0xc3, 0x9c, 0x1e, 0x87, 0x6b, 0x19, 0x3b, 0xfe,
			0x55, 0x69, 0x75, 0x3f, 0x88, 0x12, 0x8c, 0xc0,
			0x8a, 0xaa, 0x9b, 0x63, 0xd1, 0xa1, 0x6f, 0x80,
			0xef, 0x25, 0x54, 0xd7, 0x18, 0x9c, 0x41, 0x1f,
			0x58, 0x69, 0xca, 0x52, 0xc5, 0xb8, 0x3f, 0xa3,
			0x6f, 0xf2, 0x16, 0xb9, 0xc1, 0xd3, 0x00, 0x62,
			0xbe, 0xbc, 0xfd, 0x2d, 0xc5, 0xbc, 0xe0, 0x91,
			0x19, 0x34, 0xfd, 0xa7, 0x9a, 0x86, 0xf6, 0xe6,
			0x98, 0xce, 0xd7, 0x59, 0xc3, 0xff, 0x9b, 0x64,
			0x77, 0x33, 0x8f, 0x3d, 0xa4, 0xf9, 0xcd, 0x85,
			0x14, 0xea, 0x99, 0x82, 0xcc, 0xaf, 0xb3, 0x41,
			0xb2, 0x38, 0x4d, 0xd9, 0x02, 0xf3, 0xd1, 0xab,
			0x7a, 0xc6, 0x1d, 0xd2, 0x9c, 0x6f, 0x21, 0xba,
			0x5b, 0x86, 0x2f, 0x37, 0x30, 0xe3, 0x7c, 0xfd,
			0xc4, 0xfd, 0x80, 0x6c, 0x22, 0xf2, 0x21,
		};

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_xor(&ctx, data, 375);

		for(int i = 0; i < 375; i++)
			test(data[i] == ciphertext[i]);
	}

	suite("ChaCha20 Cipher Test Vector #3")
	{
		key256_t key = {
			0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a,
			0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
			0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09,
			0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
		};

		nonce96_t nonce = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x02,
		};

		uint32_t count = 42;

		uint8_t data[] = {
			0x27, 0x54, 0x77, 0x61, 0x73, 0x20, 0x62, 0x72,
			0x69, 0x6c, 0x6c, 0x69, 0x67, 0x2c, 0x20, 0x61,
			0x6e, 0x64, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
			0x6c, 0x69, 0x74, 0x68, 0x79, 0x20, 0x74, 0x6f,
			0x76, 0x65, 0x73, 0x0a, 0x44, 0x69, 0x64, 0x20,
			0x67, 0x79, 0x72, 0x65, 0x20, 0x61, 0x6e, 0x64,
			0x20, 0x67, 0x69, 0x6d, 0x62, 0x6c, 0x65, 0x20,
			0x69, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x77,
			0x61, 0x62, 0x65, 0x3a, 0x0a, 0x41, 0x6c, 0x6c,
			0x20, 0x6d, 0x69, 0x6d, 0x73, 0x79, 0x20, 0x77,
			0x65, 0x72, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20,
			0x62, 0x6f, 0x72, 0x6f, 0x67, 0x6f, 0x76, 0x65,
			0x73, 0x2c, 0x0a, 0x41, 0x6e, 0x64, 0x20, 0x74,
			0x68, 0x65, 0x20, 0x6d, 0x6f, 0x6d, 0x65, 0x20,
			0x72, 0x61, 0x74, 0x68, 0x73, 0x20, 0x6f, 0x75,
			0x74, 0x67, 0x72, 0x61, 0x62, 0x65, 0x2e,
		};

		uint8_t ciphertext[] = {
			0x62, 0xe6, 0x34, 0x7f, 0x95, 0xed, 0x87, 0xa4,
			0x5f, 0xfa, 0xe7, 0x42, 0x6f, 0x27, 0xa1, 0xdf,
			0x5f, 0xb6, 0x91, 0x10, 0x04, 0x4c, 0x0d, 0x73,
			0x11, 0x8e, 0xff, 0xa9, 0x5b, 0x01, 0xe5, 0xcf,
			0x16, 0x6d, 0x3d, 0xf2, 0xd7, 0x21, 0xca, 0xf9,
			0xb2, 0x1e, 0x5f, 0xb1, 0x4c, 0x61, 0x68, 0x71,
			0xfd, 0x84, 0xc5, 0x4f, 0x9d, 0x65, 0xb2, 0x83,
			0x19, 0x6c, 0x7f, 0xe4, 0xf6, 0x05, 0x53, 0xeb,
			0xf3, 0x9c, 0x64, 0x02, 0xc4, 0x22, 0x34, 0xe3,
			0x2a, 0x35, 0x6b, 0x3e, 0x76, 0x43, 0x12, 0xa6,
			0x1a, 0x55, 0x32, 0x05, 0x57, 0x16, 0xea, 0xd6,
			0x96, 0x25, 0x68, 0xf8, 0x7d, 0x3f, 0x3f, 0x77,
			0x04, 0xc6, 0xa8, 0xd1, 0xbc, 0xd1, 0xbf, 0x4d,
			0x50, 0xd6, 0x15, 0x4b, 0x6d, 0xa7, 0x31, 0xb1,
			0x87, 0xb5, 0x8d, 0xfd, 0x72, 0x8a, 0xfa, 0x36,
			0x75, 0x7a, 0x79, 0x7a, 0xc1, 0x88, 0xd1,
		};

		ChaCha20_Ctx ctx;
		ChaCha20_init(&ctx, key, nonce, count);
		ChaCha20_xor(&ctx, data, 127);

		for(int i = 0; i < 127; i++)
			test(data[i] == ciphertext[i]);
	}
}
