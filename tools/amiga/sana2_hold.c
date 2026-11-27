/*
 * Tachyon - SANA-II interface holder for Kickstart 1.3: opens a SANA-II device, configures it with its
 * default (ROM) station address (S2_GETSTATIONADDRESS -> S2_CONFIGINTERFACE), puts it online and then
 * keeps the device open until Ctrl-C. Started in the background before a TCP/IP stack whose own
 * S2_CONFIGINTERFACE the driver rejects: the stack then finds the interface already configured.
 * Device name from SYS:sana.txt (default devs:networks/a2065.device), unit 0. Output to SYS:sana2hold.log.
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
#define S2_GETSTATIONADDRESS 10
#define S2_CONFIGINTERFACE  11
#define S2_ONLINE           23

struct TagItem { ULONG ti_Tag; ULONG ti_Data; };
struct IOSana2Req {
    struct IORequest ios2_Req; ULONG ios2_WireError; ULONG ios2_PacketType; UBYTE ios2_SrcAddr[16]; UBYTE ios2_DstAddr[16];
    ULONG ios2_DataLength; APTR ios2_Data; APTR ios2_StatData; APTR ios2_BufferManagement;
};

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
static BPTR logfile;

static void out(const char *s) { int n = 0; while (s[n]) n++; if (logfile) Write(logfile, (APTR)s, n); }
static void out_dec(LONG v) { char b[12]; int i = 11; ULONG u = v < 0 ? (ULONG)-v : (ULONG)v; b[i] = 0; do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u); if (v < 0) b[--i] = '-'; out(b + i); }
static void out_hex(const UBYTE *p, int n) { static const char hx[] = "0123456789abcdef"; char b[3]; int i; b[2] = 0; for (i = 0; i < n; i++) { b[0] = hx[p[i] >> 4]; b[1] = hx[p[i] & 15]; out(b); if (i + 1 < n) out(":"); } }
static ULONG copy_buf(__reg("a0") UBYTE *to, __reg("a1") const UBYTE *from, __reg("d0") ULONG n) { while (n--) *to++ = *from++; return 1; }
static struct TagItem bufmgmt[] = { { S2_CopyToBuff, (ULONG)copy_buf }, { S2_CopyFromBuff, (ULONG)copy_buf }, { 0, 0 } };

static LONG sana_do(struct IOSana2Req *r, UWORD cmd, const char *name)
{
    LONG rc;
    r->ios2_Req.io_Command = cmd; r->ios2_Req.io_Flags = 0; r->ios2_Req.io_Error = 0; r->ios2_WireError = 0;
    rc = DoIO((struct IORequest *)r);
    out("sana2hold: "); out(name); out(" -> rc "); out_dec(rc); out(", io_Error "); out_dec(r->ios2_Req.io_Error); out("\n");
    return rc;
}

int main(void)
{
    static char devname[64] = "devs:networks/a2065.device";
    struct MsgPort *port; struct IOSana2Req *req; LONG rc, sig; int i; BPTR f;

    SysBase = *(struct ExecBase **)4L;
    DOSBase = (struct DosLibrary *)OpenLibrary((STRPTR)"dos.library", 0);
    if (!DOSBase) return 20;
    logfile = Open((STRPTR)"SYS:sana2hold.log", MODE_NEWFILE);
    if ((f = Open((STRPTR)"SYS:sana.txt", MODE_OLDFILE)) != 0) { LONG n = Read(f, devname, 63); Close(f); if (n > 0) { while (n > 0 && devname[n - 1] <= ' ') n--; devname[n] = 0; } }

    port = (struct MsgPort *)AllocMem(sizeof *port, MEMF_PUBLIC | MEMF_CLEAR);
    req = (struct IOSana2Req *)AllocMem(sizeof *req, MEMF_PUBLIC | MEMF_CLEAR);
    sig = AllocSignal(-1);
    if (!port || !req || sig < 0) { out("sana2hold: no memory\n"); goto end; }
    port->mp_Node.ln_Type = NT_MSGPORT; port->mp_Flags = PA_SIGNAL; port->mp_SigBit = (UBYTE)sig; port->mp_SigTask = FindTask(0);
    port->mp_MsgList.lh_Head = (struct Node *)&port->mp_MsgList.lh_Tail; port->mp_MsgList.lh_Tail = 0; port->mp_MsgList.lh_TailPred = (struct Node *)&port->mp_MsgList.lh_Head;
    req->ios2_Req.io_Message.mn_ReplyPort = port; req->ios2_Req.io_Message.mn_Length = sizeof *req; req->ios2_Req.io_Message.mn_Node.ln_Type = NT_REPLYMSG;
    req->ios2_BufferManagement = bufmgmt;
    rc = OpenDevice((STRPTR)devname, 0, (struct IORequest *)req, 0);
    out("sana2hold: OpenDevice "); out(devname); out(" -> "); out_dec(rc); out("\n");
    if (rc) goto end;
    if (!sana_do(req, S2_GETSTATIONADDRESS, "S2_GETSTATIONADDRESS")) {
        out("sana2hold: current "); out_hex(req->ios2_SrcAddr, 6); out(", default "); out_hex(req->ios2_DstAddr, 6); out("\n");
        for (i = 0; i < 16; i++) req->ios2_SrcAddr[i] = i < 6 ? req->ios2_DstAddr[i] : 0;
        if (!sana_do(req, S2_CONFIGINTERFACE, "S2_CONFIGINTERFACE (default address)")) sana_do(req, S2_ONLINE, "S2_ONLINE");
    }
    out("sana2hold: holding the device open (Ctrl-C ends)\n");
    if (logfile) { Close(logfile); logfile = 0; }
    Wait(SIGBREAKF_CTRL_C);
    CloseDevice((struct IORequest *)req);
end:
    if (logfile) Close(logfile);
    CloseLibrary((struct Library *)DOSBase);
    return 0;
}
