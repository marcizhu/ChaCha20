COMPILER         := cc
OPTIMIZATION_OPT := -O3
BASE_OPTIONS     := -pedantic-errors -Wall -Wextra -Werror -Wno-long-long -I./include
OPTIONS          := $(BASE_OPTIONS) $(OPTIMIZATION_OPT)

all: tests benchmark

tests: tests.c
	$(COMPILER) $(OPTIONS) -o tests tests.c

benchmark: bench.c
	$(COMPILER) $(OPTIONS) -o benchmark bench.c

clean:
	rm -f tests
	rm -f benchmark
