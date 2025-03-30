#ifndef __UTEST__
#define __UTEST__

#define test(...)  __test(!!(__VA_ARGS__), __FILE__, __LINE__, #__VA_ARGS__)
#define suite(...) __suite(__VA_ARGS__); if(1)

static unsigned int tst = 0, err = 0, prev = 0, once = 0;

void __test(int value, char* file, int line, char* expr)
{
	++tst;
	err += !value;
	if(!value)
	{
		if(!once)
		{
			printf("\r \x1b[31m✗\x1b[0m \n");
			once = 1;
		}
		printf("   \x1b[31m✗\x1b[0m %s:%d → %s\n", file, line, expr);
	}
}

void __suite(const char* name)
{
	if(tst > 0 && prev == err)
		printf("\r \x1b[32m✓\x1b[0m \n");

	printf("   \x1b[1m%s\x1b[0m", name);
	prev = err;
	once = 0;
}

void summary(void)
{
	if(tst > 0 && prev == err)
		printf("\r \x1b[32m✓\x1b[0m \n");

	printf("\r  \n\x1b[1m\x1b[33m    %d total", tst);
	printf("\x1b[1m\x1b[32m   %d passed", tst - err);
	printf("\x1b[1m\x1b[31m   %d failed\x1b\x1b[0m\n", err);
	exit(err);
}

#endif
