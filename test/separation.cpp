#include "separation.hpp"

size_t separation_strlen_c(const char* str)
{
    size_t cnt = 0;
    while (*str)
    {
        cnt++;
        str++;
    }
    return cnt;
}
