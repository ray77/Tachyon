/*
 * Tachyon - test of LIBS:utility.library (tools/amiga/utility13.*) on the target or under vamos:
 * tag lists with TAG_MORE/TAG_SKIP/TAG_IGNORE, PackBoolTags, UDivMod32/SDivMod32 (both results),
 * UMult32/UMult64/SMult64, Amiga2Date/Date2Amiga/CheckDate, Stricmp/ToUpper. Writes PASS/FAIL lines to
 * SYS:result.txt and SYS:done. make utility13-test (vamos).
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>

struct TagItem { ULONG ti_Tag; ULONG ti_Data; };
struct ClockData { UWORD sec, min, hour, mday, month, year, wday; };

struct TagItem *__FindTagItem(__reg("a6") void *, __reg("d0") ULONG, __reg("a0") struct TagItem *) = "\tjsr\t-30(a6)";
ULONG __GetTagData(__reg("a6") void *, __reg("d0") ULONG, __reg("d1") ULONG, __reg("a0") struct TagItem *) = "\tjsr\t-36(a6)";
ULONG __PackBoolTags(__reg("a6") void *, __reg("d0") ULONG, __reg("a0") struct TagItem *, __reg("a1") struct TagItem *) = "\tjsr\t-42(a6)";
struct TagItem *__NextTagItem(__reg("a6") void *, __reg("a0") struct TagItem **) = "\tjsr\t-48(a6)";
void __Amiga2Date(__reg("a6") void *, __reg("d0") ULONG, __reg("a0") struct ClockData *) = "\tjsr\t-120(a6)";
ULONG __Date2Amiga(__reg("a6") void *, __reg("a0") struct ClockData *) = "\tjsr\t-126(a6)";
ULONG __CheckDate(__reg("a6") void *, __reg("a0") struct ClockData *) = "\tjsr\t-132(a6)";
LONG  __SMult32(__reg("a6") void *, __reg("d0") LONG, __reg("d1") LONG) = "\tjsr\t-138(a6)";
ULONG __UMult32(__reg("a6") void *, __reg("d0") ULONG, __reg("d1") ULONG) = "\tjsr\t-144(a6)";
LONG  __SDivMod32_q(__reg("a6") void *, __reg("d0") LONG, __reg("d1") LONG) = "\tjsr\t-150(a6)";
LONG  __SDivMod32_r(__reg("a6") void *, __reg("d0") LONG, __reg("d1") LONG) = "\tjsr\t-150(a6)\n\tmove.l\td1,d0";
ULONG __UDivMod32_q(__reg("a6") void *, __reg("d0") ULONG, __reg("d1") ULONG) = "\tjsr\t-156(a6)";
ULONG __UDivMod32_r(__reg("a6") void *, __reg("d0") ULONG, __reg("d1") ULONG) = "\tjsr\t-156(a6)\n\tmove.l\td1,d0";
LONG  __Stricmp(__reg("a6") void *, __reg("a0") const char *, __reg("a1") const char *) = "\tjsr\t-162(a6)";
ULONG __ToUpper(__reg("a6") void *, __reg("d0") ULONG) = "\tjsr\t-174(a6)";
ULONG __SMult64_hi(__reg("a6") void *, __reg("d0") LONG, __reg("d1") LONG) = "\tjsr\t-198(a6)";
ULONG __SMult64_lo(__reg("a6") void *, __reg("d0") LONG, __reg("d1") LONG) = "\tjsr\t-198(a6)\n\tmove.l\td1,d0";
ULONG __UMult64_hi(__reg("a6") void *, __reg("d0") ULONG, __reg("d1") ULONG) = "\tjsr\t-204(a6)";
ULONG __UMult64_lo(__reg("a6") void *, __reg("d0") ULONG, __reg("d1") ULONG) = "\tjsr\t-204(a6)\n\tmove.l\td1,d0";

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
static BPTR con, logfile;
static int fails;

static void out(const char *s) { int n = 0; while (s[n]) n++; if (con) Write(con, (APTR)s, n); if (logfile) Write(logfile, (APTR)s, n); }
static void out_hex(ULONG v) { static const char hx[] = "0123456789abcdef"; char b[9]; int i; for (i = 7; i >= 0; i--) { b[i] = hx[v & 15]; v >>= 4; } b[8] = 0; out(b); }
static void check(const char *name, ULONG got, ULONG want)
{
    out(got == want ? "PASS " : "FAIL "); out(name); out(": "); out_hex(got);
    if (got != want) { out(" want "); out_hex(want); fails++; }
    out("\n");
}

int main(void)
{
    void *U; BPTR done;
    static struct TagItem more[] = { { 0x80000005, 55 }, { 0, 0 } };
    static struct TagItem list[] = { { 0x80000001, 11 }, { 1, 99 }, { 3, 1 }, { 0x80000009, 999 }, { 0x80000002, 22 }, { 2, 0 } };
    static struct TagItem boolmap[] = { { 0x80000001, 1 }, { 0x80000002, 2 }, { 0x80000005, 4 }, { 0, 0 } };
    static struct ClockData cd;
    struct TagItem *walk, *t; ULONG n = 0;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output();
    logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);
    more[1].ti_Tag = 0;
    list[5].ti_Data = (ULONG)more;          /* TAG_MORE -> more[] */
    U = OpenLibrary((STRPTR)"utility.library", 36);
    if (!U) { out("RESULT: utility.library did not open\n"); goto end; }
    out("utility.library version "); out_hex(((struct Library *)U)->lib_Version); out("\n");

    walk = list; while ((t = __NextTagItem(U, &walk)) != 0) n++;
    check("NextTagItem count (skip/ignore/more)", n, 3);
    check("FindTagItem via TAG_MORE", __FindTagItem(U, 0x80000005, list)->ti_Data, 55);
    check("FindTagItem skipped", (ULONG)__FindTagItem(U, 0x80000009, list), 0);
    check("GetTagData hit", __GetTagData(U, 0x80000002, 7, list), 22);
    check("GetTagData default", __GetTagData(U, 0x80000003, 7, list), 7);
    check("PackBoolTags", __PackBoolTags(U, 0x10, list, boolmap), 0x17);
    check("UDivMod32 q", __UDivMod32_q(U, 0x89abcdef, 0x1234), 495651);
    check("UDivMod32 r", __UDivMod32_r(U, 0x89abcdef, 0x1234), 4307);
    check("SDivMod32 q", (ULONG)__SDivMod32_q(U, -100, 7), (ULONG)-14);
    check("SDivMod32 r", (ULONG)__SDivMod32_r(U, -100, 7), (ULONG)-2);
    check("UMult32", __UMult32(U, 0x12345678, 0x9abcdef0), 0x242d2080);
    check("SMult32", (ULONG)__SMult32(U, -5, 7), (ULONG)-35);
    check("UMult64 hi", __UMult64_hi(U, 0xffffffff, 0xffffffff), 0xfffffffe);
    check("UMult64 lo", __UMult64_lo(U, 0xffffffff, 0xffffffff), 0x00000001);
    check("UMult64 hi 2", __UMult64_hi(U, 0xdeadbeef, 0xcafebabe), 0xb092ab7b);
    check("UMult64 lo 2", __UMult64_lo(U, 0xdeadbeef, 0xcafebabe), 0x88cf5b62);
    check("UMult64 hi 3", __UMult64_hi(U, 0x12345678, 0x9abcdef0), 0x0b00ea4e);
    check("UMult64 lo 3", __UMult64_lo(U, 0x12345678, 0x9abcdef0), 0x242d2080);
    check("SMult64 hi", __SMult64_hi(U, -5, 7), 0xffffffff);
    check("SMult64 lo", __SMult64_lo(U, -5, 7), 0xffffffdd);
    __Amiga2Date(U, 1543312800UL, &cd);
    check("Amiga2Date year", cd.year, 2026); check("Amiga2Date month", cd.month, 11); check("Amiga2Date mday", cd.mday, 27);
    check("Amiga2Date hour", cd.hour, 10); check("Amiga2Date wday (Friday)", cd.wday, 5);
    check("Date2Amiga", __Date2Amiga(U, &cd), 1543312800UL);
    check("CheckDate ok", __CheckDate(U, &cd), 1543312800UL);
    cd.mday = 31; check("CheckDate 31 Nov rejected", __CheckDate(U, &cd), 0);
    check("Stricmp equal", (ULONG)__Stricmp(U, "Utility.LIBRARY", "utility.library"), 0);
    check("Stricmp less", (ULONG)(__Stricmp(U, "abc", "abd") < 0), 1);
    check("ToUpper", __ToUpper(U, 'q'), 'Q');
    check("ToUpper latin1", __ToUpper(U, 0xe4), 0xc4);
    CloseLibrary((struct Library *)U);
    out(fails ? "RESULT: utility.library FAILED\n" : "RESULT: utility.library all checks passed\n");
end:
    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE);
    if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return fails ? 5 : 0;
}
