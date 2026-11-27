/*
 * Tachyon - utility.library for Kickstart 1.3: the C part.
 *
 * Kickstart 2.0 introduced utility.library (tag lists, hooks, dates, 32-bit mul/div, case-insensitive
 * strings). Drivers written for 2.0+, such as the Aminet a2065.device the emulated A2065 needs, open it at
 * init time and fail on 1.3 without it. This file plus tools/amiga/utility13.s make LIBS:utility.library
 * V37 with the public V36/V37/V39 functions (tag and hook functions, Amiga2Date/Date2Amiga/CheckDate,
 * SMult32/UMult32/SDivMod32/UDivMod32, Stricmp/Strnicmp/ToUpper/ToLower, ApplyTagChanges, SMult64/UMult64,
 * GetUniqueID); PackStructureTags/UnpackStructureTags and the named-object functions return 0.
 * Register parameters follow the official FD file (utility_lib.fd); vbcc keeps d2-d7/a2-a6 as the Amiga
 * library convention demands. Freestanding, no C library; divisions go through __divu in utility13.s.
 */
#include <exec/types.h>
#include <exec/memory.h>
#define SysBase (*(struct ExecBase **)4L)
#include <inline/exec_protos.h>

struct TagItem { ULONG ti_Tag; ULONG ti_Data; };
#define TAG_DONE   0UL
#define TAG_IGNORE 1UL
#define TAG_MORE   2UL
#define TAG_SKIP   3UL
#define TAG_USER   0x80000000UL
#define MAP_REMOVE_NOT_FOUND 0
#define MAP_KEEP_NOT_FOUND   1
#define TAGFILTER_AND 0
#define TAGFILTER_NOT 1

struct ClockData { UWORD sec, min, hour, mday, month, year, wday; };

/* ---- tag lists ------------------------------------------------------------------------------- */
struct TagItem *u_NextTagItem(__reg("a0") struct TagItem **pp)
{
    struct TagItem *t = *pp;
    if (!t) return 0;
    for (;;) {
        switch (t->ti_Tag) {
        case TAG_DONE:   *pp = 0; return 0;
        case TAG_IGNORE: t++; continue;
        case TAG_MORE:   t = (struct TagItem *)t->ti_Data; if (!t) { *pp = 0; return 0; } continue;
        case TAG_SKIP:   t += 1 + t->ti_Data; continue;
        default:         *pp = t + 1; return t;
        }
    }
}

struct TagItem *u_FindTagItem(__reg("d0") ULONG tag, __reg("a0") struct TagItem *list)
{
    struct TagItem *t;
    while ((t = u_NextTagItem(&list)) != 0) if (t->ti_Tag == tag) return t;
    return 0;
}

ULONG u_GetTagData(__reg("d0") ULONG tag, __reg("d1") ULONG def, __reg("a0") struct TagItem *list)
{
    struct TagItem *t = u_FindTagItem(tag, list);
    return t ? t->ti_Data : def;
}

ULONG u_PackBoolTags(__reg("d0") ULONG flags, __reg("a0") struct TagItem *list, __reg("a1") struct TagItem *boolmap)
{
    struct TagItem *t;
    while ((t = u_NextTagItem(&list)) != 0) {
        struct TagItem *m = boolmap;
        for (; m && m->ti_Tag != TAG_DONE; m++)
            if (m->ti_Tag == t->ti_Tag) { if (t->ti_Data) flags |= m->ti_Data; else flags &= ~m->ti_Data; break; }
    }
    return flags;
}

ULONG u_TagInArray(__reg("d0") ULONG tag, __reg("a0") ULONG *array)
{
    if (!array) return 0;
    for (; *array != TAG_DONE; array++) if (*array == tag) return 1;
    return 0;
}

void u_FilterTagChanges(__reg("a0") struct TagItem *changes, __reg("a1") struct TagItem *orig, __reg("d0") ULONG apply)
{
    struct TagItem *c;
    while ((c = u_NextTagItem(&changes)) != 0) {
        struct TagItem *o = u_FindTagItem(c->ti_Tag, orig);
        if (!o) continue;
        if (o->ti_Data == c->ti_Data) c->ti_Tag = TAG_IGNORE;
        else if (apply) o->ti_Data = c->ti_Data;
    }
}

void u_ApplyTagChanges(__reg("a0") struct TagItem *list, __reg("a1") struct TagItem *changes)
{
    struct TagItem *c;
    while ((c = u_NextTagItem(&changes)) != 0) {
        struct TagItem *o = u_FindTagItem(c->ti_Tag, list);
        if (o) o->ti_Data = c->ti_Data;
    }
}

void u_MapTags(__reg("a0") struct TagItem *list, __reg("a1") struct TagItem *map, __reg("d0") ULONG type)
{
    struct TagItem *t;
    while ((t = u_NextTagItem(&list)) != 0) {
        struct TagItem *m = u_FindTagItem(t->ti_Tag, map);
        if (m) t->ti_Tag = m->ti_Data == TAG_DONE ? TAG_IGNORE : m->ti_Data;
        else if (type == MAP_REMOVE_NOT_FOUND) t->ti_Tag = TAG_IGNORE;
    }
}

ULONG u_FilterTagItems(__reg("a0") struct TagItem *list, __reg("a1") ULONG *filter, __reg("d0") ULONG logic)
{
    struct TagItem *t; ULONG kept = 0;
    while ((t = u_NextTagItem(&list)) != 0) {
        ULONG in = u_TagInArray(t->ti_Tag, filter);
        if ((logic == TAGFILTER_AND) ? !in : in) t->ti_Tag = TAG_IGNORE; else kept++;
    }
    return kept;
}

/* allocation keeps its byte size in a hidden longword in front of the array */
struct TagItem *u_AllocateTagItems(__reg("d0") ULONG n)
{
    ULONG size = (n + 1) * sizeof(struct TagItem) + 8, *p;
    if (!n) return 0;
    p = (ULONG *)AllocMem(size, MEMF_PUBLIC | MEMF_CLEAR);
    if (!p) return 0;
    p[0] = size;
    return (struct TagItem *)(p + 2);
}

void u_FreeTagItems(__reg("a0") struct TagItem *list)
{
    ULONG *p;
    if (!list) return;
    p = (ULONG *)list - 2;
    FreeMem(p, p[0]);
}

struct TagItem *u_CloneTagItems(__reg("a0") struct TagItem *list)
{
    struct TagItem *walk = list, *t, *clone, *o; ULONG n = 0;
    while (u_NextTagItem(&walk)) n++;
    clone = u_AllocateTagItems(n + 1);
    if (!clone) return 0;
    walk = list; o = clone;
    while ((t = u_NextTagItem(&walk)) != 0) { *o++ = *t; }
    o->ti_Tag = TAG_DONE;
    return clone;
}

void u_RefreshTagItemClones(__reg("a0") struct TagItem *clone, __reg("a1") struct TagItem *orig)
{
    struct TagItem *c;
    if (!clone || !orig) return;
    while ((c = u_NextTagItem(&clone)) != 0) {
        struct TagItem *o = u_FindTagItem(c->ti_Tag, orig);
        if (o) c->ti_Data = o->ti_Data;
    }
}

/* ---- dates: seconds since 1978-01-01 00:00:00 (a Sunday) <-> ClockData --------------------------- */
static int leap(ULONG y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }
static const UWORD mdays[12] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

void u_Amiga2Date(__reg("d0") ULONG secs, __reg("a0") struct ClockData *cd)
{
    ULONG days = secs / 86400UL, rem = secs % 86400UL, y = 1978, m = 0, dim;
    cd->sec = (UWORD)(rem % 60); rem /= 60; cd->min = (UWORD)(rem % 60); cd->hour = (UWORD)(rem / 60);
    cd->wday = (UWORD)(days % 7);                       /* 1978-01-01 was a Sunday (0) */
    for (;;) { ULONG diy = leap(y) ? 366 : 365; if (days < diy) break; days -= diy; y++; }
    for (;;) { dim = mdays[m] + (m == 1 && leap(y) ? 1 : 0); if (days < dim) break; days -= dim; m++; }
    cd->year = (UWORD)y; cd->month = (UWORD)(m + 1); cd->mday = (UWORD)(days + 1);
}

ULONG u_Date2Amiga(__reg("a0") struct ClockData *cd)
{
    ULONG y, m, days = 0;
    for (y = 1978; y < cd->year; y++) days += leap(y) ? 366 : 365;
    for (m = 1; m < cd->month; m++) days += mdays[m - 1] + (m == 2 && leap(cd->year) ? 1 : 0);
    days += cd->mday - 1;
    return days * 86400UL + cd->hour * 3600UL + cd->min * 60UL + cd->sec;
}

ULONG u_CheckDate(__reg("a0") struct ClockData *cd)
{
    struct ClockData t; ULONG s;
    if (cd->year < 1978 || cd->month < 1 || cd->month > 12 || cd->mday < 1 || cd->hour > 23 || cd->min > 59 || cd->sec > 59) return 0;
    if (cd->mday > mdays[cd->month - 1] + (cd->month == 2 && leap(cd->year) ? 1 : 0)) return 0;
    s = u_Date2Amiga(cd);
    u_Amiga2Date(s, &t);
    if (t.wday != cd->wday) return 0;
    return s;
}

/* ---- strings (ASCII + ISO 8859-1) -------------------------------------------------------------- */
ULONG u_ToUpper(__reg("d0") ULONG c)
{
    c &= 255;
    if ((c >= 'a' && c <= 'z') || (c >= 0xe0 && c <= 0xfe && c != 0xf7)) return c - 32;
    return c;
}
ULONG u_ToLower(__reg("d0") ULONG c)
{
    c &= 255;
    if ((c >= 'A' && c <= 'Z') || (c >= 0xc0 && c <= 0xde && c != 0xd7)) return c + 32;
    return c;
}
LONG u_Strnicmp(__reg("a0") const UBYTE *a, __reg("a1") const UBYTE *b, __reg("d0") LONG n)
{
    while (n-- > 0) {
        ULONG ca = u_ToLower(*a), cb = u_ToLower(*b);
        if (ca != cb) return (LONG)ca - (LONG)cb;
        if (!ca) return 0;
        a++; b++;
    }
    return 0;
}
LONG u_Stricmp(__reg("a0") const UBYTE *a, __reg("a1") const UBYTE *b) { return u_Strnicmp(a, b, 0x7fffffff); }

/* ---- the rest ------------------------------------------------------------------------------------ */
static ULONG unique_id = 1;
ULONG u_GetUniqueID(void) { ULONG v; Forbid(); v = unique_id++; Permit(); return v; }
ULONG u_Zero(void) { return 0; }
