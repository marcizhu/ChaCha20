# ChaCha20 Algorithm Implementation :closed_lock_with_key:

Small, fast & straightforward C library to encrypt and/or decrypt blocks of data using Daniel Bernstein's excellent ChaCha20 encryption algorithm as described in RFC 7539.

This library requires no dynamic memory, and only uses 64 bytes per each ChaCha20 context plus an additional 64-byte array used as a temporary buffer when encrypting/decripting (so a total of 128 bytes of memory needed). Because of this, the library is easily embeddable in microcontrollers and can easily be used from other languages such as C++ due to its simple interface (only 2 API calls).

## Example usage

In order to encrypt (or decrypt) a block of data, you will need a 256-bit key as an 8-byte array, a 96-bit nonce and the data itself. First, a ChaCha20 context must be initialized by calling `ChaCha20_init()` with the ChaCha20 context, key, the nonce and the block count. Then, the block of data can be encrypted or decrypted by calling `ChaCha20_xor()` with the context and the buffer of data. The data will be encrypted/decrypted in place.

The following snippet shows a simple example of how to encrypt (or decrypt) a block of data:

```c
#define CHACHA20_IMPLEMENTATION
#include "ChaCha20.h"

int main()
{
	key256_t key = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	};

	nonce96_t nonce = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00,
	};

	uint32_t count = 0x00000001;

	uint8_t data[] = {
		0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61,
		0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
		// ...
		0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
		0x74, 0x2e,
	};

	ChaCha20_Ctx ctx;
	ChaCha20_init(&ctx, key, nonce, count);
	ChaCha20_xor(&ctx, data, sizeof(data));
	// The array 'data' is now encrypted (or decrypted if it
	// was already encrypted)
}
```

ChaCha20 uses an XOR between the data and a key stream, so the same operation is used both for encryption and decryption. This process allows in-place encryption/decryption, further reducing memory usage.

Please refer to the file [ChaCha20.h](https://github.com/marcizhu/ChaCha20/blob/master/ChaCha20.h) for the API documentation, as well as the files [tests.c](https://github.com/marcizhu/ChaCha20/blob/master/tests.c) and [bench.c](https://github.com/marcizhu/ChaCha20/blob/master/bench.c) for more examples.

## Benchmarks

This library has been benchmarked on a MacBook Pro 2018, with an Intel Core i5 @ 2.3GHz (4 cores). The compiler used is Apple clang version 13.0.0, with `-O3` optimization level. Here are the results:

| Test Case                    | Minimum | Average | Maximum | Average Speed |
|:-----------------------------|:-------:|:-------:|:-------:|:-------------:|
| Initialization               | 5.70 ns | 5.47 ns | 7.64 ns | ~182M calls/s |
| Encryption (16-byte blocks)  | 7.07 ns | 7.45 ns | 8.07 ns |   ~134 MB/s   |
| Encryption (64-byte blocks)  | 1.76 ns | 1.79 ns | 2.09 ns |   ~558 MB/s   |
| Encryption (256-byte blocks) | 1.73 ns | 1.79 ns | 2.47 ns |   ~558 MB/s   |

As always, YMMV. In case you want to benchmark this library yourself, I recommend using the included program [bench.c](https://github.com/marcizhu/ChaCha20/blob/master/bench.c). The reported time for initialization is the time needed for a single call to `ChaCha20_init()`, while the time for the encryption benchmark is the min/avg/max time taken to encrypt a single byte. Thus, the speed is given by the formula: `1/time(s)`.

## Compiling
The included Makefile will compile the library into a static library as well as compile the tests and benchmark. You can also use the provided `CMakeLists.txt` in order to compile this library into a static library or integrate this project with yours.

## Security
This library is RFC 7539-compliant, and the code is small to there's not a lot of bug surface area. It uses 256-bit keys and 96-bit nonce as well as a well-regarded, modern and widely used algorithm. Additionally, all available test vectors are executed on CI/CD after each commit, so it should be pretty robust.

However, please note that this software **does not** offer any warranty. This library is for encrypting your AWS secrets, not for classified war plans or the pictures of the aliens from Roswell.

## License
Copyright (c) 2022 Marc Izquierdo  
This library is licensed under the [MIT License](https://choosealicense.com/licenses/mit/). See
[LICENSE](https://github.com/marcizhu/ChaCha20/blob/master/LICENSE) for more details.
