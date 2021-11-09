#include "common.h"

typedef int (*fn_callback)(int);
typedef int(*fn_sig)(int, int, fn_callback);

static int _callback_square(int num)
{
    return num * num;
}

DISABLE_OPTIMIZE
static int add(int a, int b, fn_callback cb)
{
    return cb(a + b);
}

static int del(int a, int b, fn_callback cb)
{
    return cb(a - b);
}

TEST(callback)
{
    ASSERT_EQ_D32(add(1, 2, _callback_square), 9);

    fn_sig fn_orig;
    ASSERT_EQ_D32(inline_hook_inject((void**)&fn_orig, (void*)add, (void*)del), 0);
    ASSERT_NE_PTR(fn_orig, NULL);

    ASSERT_EQ_D32(add(1, 2, _callback_square), 1);
    ASSERT_EQ_D32(fn_orig(1, 2, _callback_square), 9);

    inline_hook_uninject((void**)&fn_orig);
    ASSERT_EQ_PTR(fn_orig, NULL);
    ASSERT_EQ_D32(add(1, 2, _callback_square), 9);
}
