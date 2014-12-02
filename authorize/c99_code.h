/* This file adds support for snprintf (C99+ standard function)
 * that is not available for visual studio.
 *
 * Thanks to Valentin Milea for posting this solution in Stack Overflow
 * (http://stackoverflow.com/questions/2915672/snprintf-and-visual-studio-2010)
 */
#ifdef _MSC_VER

#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>

#define snprintf c99_snprintf

int c99_vsnprintf(char* str, size_t size, const char* format, va_list ap)
{
    int count = -1;

    if (size != 0)
        count = _vsnprintf_s(str, size, _TRUNCATE, format, ap);
    if (count == -1)
        count = _vscprintf(format, ap);

    return count;
}

int c99_snprintf(char* str, size_t size, const char* format, ...)
{

    int count;
	va_list ap;

    va_start(ap, format);
    count = c99_vsnprintf(str, size, format, ap);
    va_end(ap);

    return count;
}
#endif // _MSC_VER