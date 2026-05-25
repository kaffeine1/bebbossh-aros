#if defined(__AROS__)

#include <fnmatch.h>

static int fold_char(int c, int flags)
{
    if ((flags & FNM_IGNORECASE) && c >= 'A' && c <= 'Z')
        return c + ('a' - 'A');
    return c;
}

static int match_here(const char *pattern, const char *string, int flags)
{
    for (;;) {
        int pc = (unsigned char)*pattern++;
        if (!pc)
            return *string ? FNM_NOMATCH : 0;
        if (pc == '*') {
            while (*pattern == '*')
                ++pattern;
            if (!*pattern)
                return 0;
            for (;;) {
                if (match_here(pattern, string, flags) == 0)
                    return 0;
                if (!*string)
                    return FNM_NOMATCH;
                ++string;
            }
        }
        if (!*string)
            return FNM_NOMATCH;
        if (pc != '?' && fold_char(pc, flags) != fold_char((unsigned char)*string, flags))
            return FNM_NOMATCH;
        ++string;
    }
}

int fnmatch(const char *pattern, const char *string, int flags)
{
    if (!pattern || !string)
        return FNM_NOMATCH;
    return match_here(pattern, string, flags);
}

#endif
