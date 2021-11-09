#include "common.h"

typedef int(*fn_sig)(int, int);

static int sum(int a, int b)
{
    int i;
    int ret = 0;
    for (i = a; i <= b; i++)
    {
        ret += i;
    }
    return ret;
}

static int del(int a, int b)
{
    int i;
    int ret = 0;
    for (i = a; i <= b; i++)
    {
        ret -= i;
    }
    return ret;
}

TEST(simple)
{
    ASSERT_EQ_D32(sum(1, 10), 55);

    fn_sig fn_orig;
    ASSERT_EQ_D32(inline_hook_inject((void**)&fn_orig, (void*)sum, (void*)del), 0);
    ASSERT_NE_PTR(fn_orig, NULL);

    ASSERT_EQ_D32(sum(1, 10), -55);
    ASSERT_EQ_D32(fn_orig(1, 10), 55);

    inline_hook_uninject((void**)&fn_orig);
    ASSERT_EQ_PTR(fn_orig, NULL);
    ASSERT_EQ_D32(sum(1, 10), 55);
}
