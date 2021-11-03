#include "common.h"

typedef int(*fn_sig)(int, int);

static int add(int a, int b)
{
	return a + b;
}

static int del(int a, int b)
{
	return a - b;
}

TEST(simple)
{
	ASSERT_EQ_D32(add(1, 2), 3);

	fn_sig fn_orig;
	ASSERT_EQ_D32(inline_hook_inject((void**)&fn_orig, (void*)add, (void*)del), 0);
	ASSERT_NE_PTR(fn_orig, NULL);

	ASSERT_EQ_D32(add(1, 2), -1);
	ASSERT_EQ_D32(fn_orig(1, 2), 3);

	inline_hook_uninject((void**)&fn_orig);
	ASSERT_EQ_PTR(fn_orig, NULL);
	ASSERT_EQ_D32(add(1, 2), 3);
}
