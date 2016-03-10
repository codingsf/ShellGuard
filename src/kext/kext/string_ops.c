
#include "string_ops.h"

int MAX_VAL = 2147483647;


char* strstr(char *haystack, char *needle)
{
    char c, sc;
    size_t len;
    
    if ((c = * needle ++) != 0) {
        len = strlen(needle);
        do {
            do {
                if ((sc = *haystack++) == 0) return (NULL);
            }
            while (sc != c);
        }
        while (strncmp(haystack, needle, len) != 0);
        haystack--;
    }
    return ((char *) haystack);
}

//int32_t startswith(const char *a, const char *b)
//{
//    return (strncmp(a, b, strlen(b)) == 0) ? 1 : 0;
//}


const char* byte_to_binary(int x)
{
    static char b[33];
    b[0] = '\0';
    char *p = b;
    for (int z = MAX_VAL; z > 0; z >>= 1) {
        *p++ = (x & z) ? '1' : '0';
    }
    return b;
}