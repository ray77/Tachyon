/*
 * Tachyon - SANA-II driver probe for Kickstart 1.3: opens a SANA-II device directly (no TCP/IP stack),
 * runs S2_DEVICEQUERY, S2_GETSTATIONADDRESS, S2_CONFIGINTERFACE, S2_ONLINE and one ARP request/reply
 * through the driver, logging every return and error code to SYS:result.txt. Written to see what the
 * Aminet a2065.device does on the emulated A2065 (FS-UAE slirp: gateway 10.0.2.2) and which station
 * address it accepts, after TheWire13 reported S2_CONFIGINTERFACE failing with S2ERR_BAD_ADDRESS.
 * Device name from SYS:sana.txt (default devs:networks/a2065.device), unit 0. make sana2-probe / run-sana2.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/ports.h>
#include <exec/io.h>
#include <exec/memory.h>
#include <dos/dos.h>
#include <proto/exec.h>
#include <proto/dos.h>

#define S2_DUMMY            (0x80000000UL + 0xB0000UL)
#define S2_CopyToBuff       (S2_DUMMY + 1)
#define S2_CopyFromBuff     (S2_DUMMY + 2)
#define S2_DEVICEQUERY      9
#define S2_GETSTATIONADDRESS 10
#define S2_CONFIGINTERFACE  11
#define S2_GETGLOBALSTATS   20
#define S2_ONLINE           23
#define S2_OFFLINE          24
#define SANA2IOF_BCAST      0x40

struct TagItem { ULONG ti_Tag; ULONG ti_Data; };
struct IOSana2Req {
    struct IORequest ios2_Req;          /* 32 bytes */
    ULONG ios2_WireError;
    ULONG ios2_PacketType;
    UBYTE ios2_SrcAddr[16];
    UBYTE ios2_DstAddr[16];
    ULONG ios2_DataLength;
    APTR  ios2_Data;
    APTR  ios2_StatData;
    APTR  ios2_BufferManagement;
};
struct Sana2DeviceQuery { ULONG SizeAvailable, SizeSupplied, DevQueryFormat, DeviceLevel; UWORD AddrFieldSize; ULONG MTU, BPS, HardwareType; };

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
static BPTR con, logfile;

static void out(const char *s) { int n = 0; while (s[n]) n++; if (con) Write(con, (APTR)s, n); if (logfile) Write(logfile, (APTR)s, n); }
static void out_dec(LONG v) { char b[12]; int i = 11; ULONG u = v < 0 ? (ULONG)-v : (ULONG)v; b[i] = 0; do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u); if (v < 0) b[--i] = '-'; out(b + i); }
static void out_hex(const UBYTE *p, int n) { static const char hx[] = "0123456789abcdef"; char b[3]; int i; b[2] = 0; for (i = 0; i < n; i++) { b[0] = hx[p[i] >> 4]; b[1] = hx[p[i] & 15]; out(b); if (i + 1 < n) out(":"); } }
static void out_ip(const UBYTE *p) { int i; for (i = 0; i < 4; i++) { out_dec(p[i]); if (i < 3) out("."); } }

/* SANA-II buffer management: the driver copies frames with these (to a0, from a1, length d0) */
static ULONG copy_buf(__reg("a0") UBYTE *to, __reg("a1") const UBYTE *from, __reg("d0") ULONG n) { while (n--) *to++ = *from++; return 1; }
static struct TagItem bufmgmt[] = { { S2_CopyToBuff, (ULONG)copy_buf }, { S2_CopyFromBuff, (ULONG)copy_buf }, { 0, 0 } };

static struct MsgPort *make_port(void)
{
    struct MsgPort *mp = (struct MsgPort *)AllocMem(sizeof *mp, MEMF_PUBLIC | MEMF_CLEAR);
    LONG sig = AllocSignal(-1);
    if (!mp || sig < 0) return 0;
    mp->mp_Node.ln_Type = NT_MSGPORT; mp->mp_Flags = PA_SIGNAL; mp->mp_SigBit = (UBYTE)sig; mp->mp_SigTask = FindTask(0);
    mp->mp_MsgList.lh_Head = (struct Node *)&mp->mp_MsgList.lh_Tail; mp->mp_MsgList.lh_Tail = 0;
    mp->mp_MsgList.lh_TailPred = (struct Node *)&mp->mp_MsgList.lh_Head;
    return mp;
}

static LONG sana_do(struct IOSana2Req *r, UWORD cmd, const char *name)
{
    LONG rc;
    r->ios2_Req.io_Command = cmd; r->ios2_Req.io_Flags = 0; r->ios2_Req.io_Error = 0; r->ios2_WireError = 0;
    rc = DoIO((struct IORequest *)r);
    out("sana: "); out(name); out(" -> rc "); out_dec(rc); out(", io_Error "); out_dec(r->ios2_Req.io_Error); out(", WireError "); out_dec((LONG)r->ios2_WireError); out("\n");
    return rc;
}

int main(void)
{
    static char devname[64] = "devs:networks/a2065.device";
    static struct Sana2DeviceQuery dq;
    static UBYTE arp[64], rxbuf[1600], our[6], dflt[6];
    struct MsgPort *port; struct IOSana2Req *req, *rd; LONG rc; int i, ok = 0;
    BPTR f, done;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    con = Output(); logfile = Open((STRPTR)"SYS:result.txt", MODE_NEWFILE);
    if ((f = Open((STRPTR)"SYS:sana.txt", MODE_OLDFILE)) != 0) { LONG n = Read(f, devname, 63); Close(f); if (n > 0) { while (n > 0 && devname[n - 1] <= ' ') n--; devname[n] = 0; } }
    out("Tachyon SANA-II probe: "); out(devname); out(" unit 0\n");

    port = make_port();
    req = (struct IOSana2Req *)AllocMem(sizeof *req, MEMF_PUBLIC | MEMF_CLEAR);
    rd = (struct IOSana2Req *)AllocMem(sizeof *rd, MEMF_PUBLIC | MEMF_CLEAR);
    if (!port || !req || !rd) { out("RESULT: no memory\n"); goto end; }
    req->ios2_Req.io_Message.mn_ReplyPort = port; req->ios2_Req.io_Message.mn_Length = sizeof *req; req->ios2_Req.io_Message.mn_Node.ln_Type = NT_REPLYMSG;
    req->ios2_BufferManagement = bufmgmt;
    rc = OpenDevice((STRPTR)devname, 0, (struct IORequest *)req, 0);
    out("sana: OpenDevice -> "); out_dec(rc); out(" (io_Error "); out_dec(req->ios2_Req.io_Error); out(")\n");
    if (rc) { out("RESULT: OpenDevice failed\n"); goto end; }
    {   struct Library *dev = (struct Library *)req->ios2_Req.io_Device;
        out("sana: device "); out((const char *)dev->lib_Node.ln_Name); out(" version "); out_dec(dev->lib_Version); out("."); out_dec(dev->lib_Revision); out("\n"); }

    dq.SizeAvailable = sizeof dq; req->ios2_StatData = &dq;
    if (!sana_do(req, S2_DEVICEQUERY, "S2_DEVICEQUERY")) {
        out("sana: query: SizeSupplied "); out_dec((LONG)dq.SizeSupplied); out(", DeviceLevel "); out_dec((LONG)dq.DeviceLevel); out(", AddrFieldSize "); out_dec(dq.AddrFieldSize);
        out(" bits, MTU "); out_dec((LONG)dq.MTU); out(", BPS "); out_dec((LONG)dq.BPS); out(", HardwareType "); out_dec((LONG)dq.HardwareType); out("\n");
    }
    if (!sana_do(req, S2_GETSTATIONADDRESS, "S2_GETSTATIONADDRESS")) {
        out("sana: current address "); out_hex(req->ios2_SrcAddr, 6); out(", default (ROM) address "); out_hex(req->ios2_DstAddr, 6); out("\n");
        for (i = 0; i < 6; i++) dflt[i] = req->ios2_DstAddr[i];
    }
    /* configure with the default address, as AmiTCP does */
    for (i = 0; i < 16; i++) req->ios2_SrcAddr[i] = 0;
    for (i = 0; i < 6; i++) req->ios2_SrcAddr[i] = dflt[i];
    rc = sana_do(req, S2_CONFIGINTERFACE, "S2_CONFIGINTERFACE (default address)");
    if (rc) {
        /* second try: zero address (what a stack that skips GETSTATIONADDRESS might send) */
        for (i = 0; i < 16; i++) req->ios2_SrcAddr[i] = 0;
        rc = sana_do(req, S2_CONFIGINTERFACE, "S2_CONFIGINTERFACE (zero address)");
    }
    if (rc) {
        /* third try: a Commodore-OUI address with the ROM's low bytes */
        for (i = 0; i < 16; i++) req->ios2_SrcAddr[i] = 0;
        req->ios2_SrcAddr[0] = 0x00; req->ios2_SrcAddr[1] = 0x80; req->ios2_SrcAddr[2] = 0x10;
        req->ios2_SrcAddr[3] = dflt[3]; req->ios2_SrcAddr[4] = dflt[4]; req->ios2_SrcAddr[5] = dflt[5];
        rc = sana_do(req, S2_CONFIGINTERFACE, "S2_CONFIGINTERFACE (00:80:10 + ROM low bytes)");
    }
    if (!sana_do(req, S2_GETSTATIONADDRESS, "S2_GETSTATIONADDRESS after configure")) {
        out("sana: current address "); out_hex(req->ios2_SrcAddr, 6); out("\n");
        for (i = 0; i < 6; i++) our[i] = req->ios2_SrcAddr[i];
    }
    if (rc) { out("RESULT: S2_CONFIGINTERFACE rejected every address\n"); goto close; }
    sana_do(req, S2_ONLINE, "S2_ONLINE");

    /* ARP request for the slirp gateway 10.0.2.2 from 10.0.2.15; a reply proves LANCE emulation + slirp */
    *rd = *req; rd->ios2_Req.io_Message.mn_ReplyPort = port;
    rd->ios2_PacketType = 0x0806; rd->ios2_Data = rxbuf; rd->ios2_DataLength = sizeof rxbuf;
    rd->ios2_Req.io_Command = CMD_READ; rd->ios2_Req.io_Flags = 0;
    SendIO((struct IORequest *)rd);
    for (i = 0; i < 64; i++) arp[i] = 0;
    arp[1] = 1; arp[2] = 8; arp[3] = 0; arp[4] = 6; arp[5] = 4; arp[7] = 1;                /* ethernet, IPv4, request */
    for (i = 0; i < 6; i++) arp[8 + i] = our[i];
    arp[14] = 10; arp[15] = 0; arp[16] = 2; arp[17] = 15;                                 /* sender 10.0.2.15 */
    arp[24] = 10; arp[25] = 0; arp[26] = 2; arp[27] = 2;                                  /* target 10.0.2.2 */
    req->ios2_PacketType = 0x0806; req->ios2_Data = arp; req->ios2_DataLength = 28;
    for (i = 0; i < 16; i++) req->ios2_DstAddr[i] = i < 6 ? 0xff : 0;
    req->ios2_Req.io_Command = CMD_WRITE; req->ios2_Req.io_Flags = SANA2IOF_BCAST; req->ios2_Req.io_Error = 0;
    rc = DoIO((struct IORequest *)req);
    out("sana: CMD_WRITE ARP request (28 bytes, broadcast) -> rc "); out_dec(rc); out(", io_Error "); out_dec(req->ios2_Req.io_Error); out(", WireError "); out_dec((LONG)req->ios2_WireError); out("\n");
    for (i = 0; i < 60; i++) { if (CheckIO((struct IORequest *)rd)) break; Delay(5); }
    if (CheckIO((struct IORequest *)rd)) {
        WaitIO((struct IORequest *)rd);
        out("sana: CMD_READ got ARP frame after "); out_dec(i * 100); out(" ms: io_Error "); out_dec(rd->ios2_Req.io_Error); out(", "); out_dec((LONG)rd->ios2_DataLength);
        out(" bytes from "); out_hex(rd->ios2_SrcAddr, 6); out(" op "); out_dec(rxbuf[7]); out(", sender "); out_hex(rxbuf + 8, 6); out(" = "); out_ip(rxbuf + 14); out("\n");
        ok = rd->ios2_Req.io_Error == 0 && rxbuf[7] == 2;
    } else {
        AbortIO((struct IORequest *)rd); WaitIO((struct IORequest *)rd);
        out("sana: no ARP reply within 6 s\n");
    }
    sana_do(req, S2_OFFLINE, "S2_OFFLINE");
close:
    CloseDevice((struct IORequest *)req);
    out(ok ? "RESULT: SANA-II path works (ARP reply from the gateway)\n" : "RESULT: SANA-II path incomplete, see above\n");
end:
    if (logfile) Close(logfile);
    done = Open((STRPTR)"SYS:done", MODE_NEWFILE); if (done) Close(done);
    CloseLibrary((struct Library *)DOSBase);
    return ok ? 0 : 5;
}
