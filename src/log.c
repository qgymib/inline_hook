#include "log.h"

static char _log_ascii_to_char(unsigned char c)
{
    if (c >= 32 && c <= 126)
    {
        return c;
    }
    return '.';
}

API_LOCAL
void dump_hex(const void* data, size_t size, size_t width)
{
    const unsigned char* pdat = data;

    size_t idx_line;
    for (idx_line = 0; idx_line < size; idx_line += width)
    {
        printf("%p | ", &pdat[idx_line]);

        size_t idx_colume;
        /* printf hex */
        for (idx_colume = 0; idx_colume < width; idx_colume++)
        {
            const char* postfix = (idx_colume < width - 1) ? "" : "|";

            if (idx_colume + idx_line < size)
            {
                printf("%02x %s", pdat[idx_colume + idx_line], postfix);
            }
            else
            {
                printf("   %s", postfix);
            }
        }
        printf(" ");
        /* printf char */
        for (idx_colume = 0; (idx_colume < width) && (idx_colume + idx_line < size); idx_colume++)
        {
            printf("%c", _log_ascii_to_char(pdat[idx_colume + idx_line]));
        }
        printf("\n");
    }
}
