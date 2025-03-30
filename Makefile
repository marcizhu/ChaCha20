COMPILER         := cc
OPTIMIZATION_OPT := -O3
BASE_OPTIONS     := -pedantic-errors -Wall -Wextra -Werror -Wno-long-long -I.
OPTIONS          := $(BASE_OPTIONS) $(OPTIMIZATION_OPT)

all: tests benchmark examples

examples: ChaCha20.h examples/chunked_cypher.c examples/simple_cypher.c
	$(COMPILER) $(OPTIONS) -o simple-cypher examples/simple_cypher.c
	$(COMPILER) $(OPTIONS) -o chunked-cypher examples/chunked_cypher.c

tests: ChaCha20.h tests.c
	$(COMPILER) $(OPTIONS) -o tests tests.c

benchmark: ChaCha20.h bench.c
	$(COMPILER) $(OPTIONS) -o benchmark bench.c

clean:
	rm -f tests
	rm -f benchmark
	rm -f simple-cypher chunked-cypher
