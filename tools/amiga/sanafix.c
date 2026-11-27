/*
 * Tachyon - a2065fix.device: transparent SANA-II wrapper around a2065.device for stacks that configure the
 * interface with the unit's *current* station address. The Aminet a2065.device (2.16) reports
 * ff:ff:ff:ff:ff:ff as current address before S2_CONFIGINTERFACE and rejects that broadcast address with
 * S2ERR_BAD_ADDRESS; TheWire13 configures with the current address and aborts (docs/NETWORK.md 4).
 *
 * The wrapper opens the real device with a private request and sits in the path for the synchronous
 * control commands: S2_GETSTATIONADDRESS reports the default (ROM) address as current while the unit is
 * unconfigured, S2_CONFIGINTERFACE replaces a broadcast/zero address with the default one and treats
 * "already configured" as success. Data commands (CMD_READ, CMD_WRITE, multicast/broadcast, events,
 * orphans) are handed to the real device with the request re-pointed at it, so they run at full speed
 * and later requests on that IORequest go to the driver directly. Kickstart 1.3, no utility.library needed
 * by the wrapper itself. Build: tools/amiga/sanafix.s + this file -> DEVS:Networks/a2065fix.device.
 */
#include <exec/types.h>
#include <exec/execbase.h>
#include <exec/ports.h>
#include <exec/io.h>
#include <exec/memory.h>
#include <exec/errors.h>
#define SysBase (*(struct ExecBase **)4L)
#include <inline/exec_protos.h>

#define REAL_DEVICE "devs:networks/a2065.device"

#define S2_DEVICEQUERY       9
#define S2_GETSTATIONADDRESS 10
#define S2_CONFIGINTERFACE   11
#define S2_ADDMULTICASTADDRESS 12
#define S2_DELMULTICASTADDRESS 13
#define S2_MULTICAST         14
#define S2_BROADCAST         15
#define S2_TRACKTYPE         16
#define S2_UNTRACKTYPE       17
#define S2_GETTYPESTATS      18
#define S2_GETSPECIALSTATS   19
#define S2_GETGLOBALSTATS    20
#define S2_ONEVENT           21
#define S2_READORPHAN        22
#define S2_ONLINE            23
#define S2_OFFLINE           24
#define S2ERR_BAD_STATE      4
#define S2WERR_IS_CONFIGURED 15

struct IOSana2Req {
    struct IORequest ios2_Req; ULONG ios2_WireError; ULONG ios2_PacketType; UBYTE ios2_SrcAddr[16]; UBYTE ios2_DstAddr[16];
    ULONG ios2_DataLength; APTR ios2_Data; APTR ios2_StatData; APTR ios2_BufferManagement;
};

/* one per OpenDevice: the real device, a private request and its reply port (owned by the opening task) */
struct fix_unit {
    struct Library *real; APTR realunit;
    struct MsgPort port;
    struct IOSana2Req preq;
    UBYTE dflt[6]; int have_dflt;
};

void __RealBeginIO(__reg("a6") void *, __reg("a1") struct IORequest *) = "\tjsr\t-30(a6)";

static void cp(UBYTE *d, const UBYTE *s, ULONG n) { while (n--) *d++ = *s++; }
static int is_bcast_or_zero(const UBYTE *a)
{
    int i, z = 1, b = 1;
    for (i = 0; i < 6; i++) { if (a[i]) z = 0; if (a[i] != 0xff) b = 0; }
    return z || b;
}

/* synchronous command on the real device through the private request; returns io_Error */
static LONG real_do(struct fix_unit *u, UWORD cmd)
{
    u->preq.ios2_Req.io_Command = cmd; u->preq.ios2_Req.io_Flags = 0; u->preq.ios2_Req.io_Error = 0; u->preq.ios2_WireError = 0;
    u->preq.ios2_Req.io_Device = (struct Device *)u->real; u->preq.ios2_Req.io_Unit = (struct Unit *)u->realunit;
    DoIO((struct IORequest *)&u->preq);
    return u->preq.ios2_Req.io_Error;
}

static void learn_default(struct fix_unit *u)
{
    if (u->have_dflt) return;
    if (!real_do(u, S2_GETSTATIONADDRESS)) { cp(u->dflt, u->preq.ios2_DstAddr, 6); u->have_dflt = 1; }
}

/* ---- device vectors (called from the table in sanafix.s) ----------------------------------------- */
void fix_open(__reg("a6") struct Library *dev, __reg("a1") struct IOSana2Req *req, __reg("d0") ULONG unitnum, __reg("d1") ULONG flags)
{
    struct fix_unit *u; LONG sig;
    req->ios2_Req.io_Error = IOERR_OPENFAIL;
    u = (struct fix_unit *)AllocMem(sizeof *u, MEMF_PUBLIC | MEMF_CLEAR);
    if (!u) return;
    sig = AllocSignal(-1);
    if (sig < 0) { FreeMem(u, sizeof *u); return; }
    u->port.mp_Node.ln_Type = NT_MSGPORT; u->port.mp_Flags = PA_SIGNAL; u->port.mp_SigBit = (UBYTE)sig; u->port.mp_SigTask = FindTask(0);
    u->port.mp_MsgList.lh_Head = (struct Node *)&u->port.mp_MsgList.lh_Tail; u->port.mp_MsgList.lh_Tail = 0;
    u->port.mp_MsgList.lh_TailPred = (struct Node *)&u->port.mp_MsgList.lh_Head;
    u->preq.ios2_Req.io_Message.mn_ReplyPort = &u->port; u->preq.ios2_Req.io_Message.mn_Length = sizeof u->preq;
    u->preq.ios2_Req.io_Message.mn_Node.ln_Type = NT_REPLYMSG;
    u->preq.ios2_BufferManagement = req->ios2_BufferManagement;     /* the stack's copy routines serve the real driver */
    if (OpenDevice((STRPTR)REAL_DEVICE, unitnum, (struct IORequest *)&u->preq, flags) != 0) {
        req->ios2_Req.io_Error = u->preq.ios2_Req.io_Error ? u->preq.ios2_Req.io_Error : IOERR_OPENFAIL;
        FreeSignal(sig); FreeMem(u, sizeof *u); return;
    }
    u->real = (struct Library *)u->preq.ios2_Req.io_Device; u->realunit = u->preq.ios2_Req.io_Unit;
    req->ios2_Req.io_Device = (struct Device *)dev; req->ios2_Req.io_Unit = (struct Unit *)u;
    req->ios2_Req.io_Error = 0;
    dev->lib_OpenCnt++;
}

ULONG fix_close(__reg("a6") struct Library *dev, __reg("a1") struct IOSana2Req *req)
{
    struct fix_unit *u = (struct fix_unit *)req->ios2_Req.io_Unit;
    if (u) {
        CloseDevice((struct IORequest *)&u->preq);
        FreeSignal(u->port.mp_SigBit);
        FreeMem(u, sizeof *u);
    }
    req->ios2_Req.io_Device = (struct Device *)-1; req->ios2_Req.io_Unit = (struct Unit *)-1;
    if (dev->lib_OpenCnt) dev->lib_OpenCnt--;
    return 0;                       /* never expunged */
}

void fix_beginio(__reg("a6") struct Library *dev, __reg("a1") struct IOSana2Req *req)
{
    struct fix_unit *u = (struct fix_unit *)req->ios2_Req.io_Unit;
    UWORD cmd = req->ios2_Req.io_Command; LONG err;
    (void)dev;
    switch (cmd) {
    case CMD_READ: case CMD_WRITE: case S2_MULTICAST: case S2_BROADCAST: case S2_ONEVENT: case S2_READORPHAN:
        /* data path: straight to the driver, which replies to the stack's port itself */
        req->ios2_Req.io_Device = (struct Device *)u->real; req->ios2_Req.io_Unit = (struct Unit *)u->realunit;
        __RealBeginIO(u->real, (struct IORequest *)req);
        return;
    default:
        break;
    }
    /* control path: synchronously through the private request */
    u->preq.ios2_PacketType = req->ios2_PacketType; cp(u->preq.ios2_SrcAddr, req->ios2_SrcAddr, 16); cp(u->preq.ios2_DstAddr, req->ios2_DstAddr, 16);
    u->preq.ios2_DataLength = req->ios2_DataLength; u->preq.ios2_Data = req->ios2_Data; u->preq.ios2_StatData = req->ios2_StatData;
    if (cmd == S2_CONFIGINTERFACE) {
        learn_default(u);
        if (u->have_dflt && is_bcast_or_zero(req->ios2_SrcAddr)) { cp(u->preq.ios2_SrcAddr, u->dflt, 6); }
    }
    err = real_do(u, cmd);
    if (cmd == S2_CONFIGINTERFACE && err == S2ERR_BAD_STATE && u->preq.ios2_WireError == S2WERR_IS_CONFIGURED) {
        /* someone (sana2hold, an earlier opener) configured the unit already: report success with its address */
        err = 0; u->preq.ios2_WireError = 0;
        if (!real_do(u, S2_GETSTATIONADDRESS)) { /* SrcAddr = current */ }
        u->preq.ios2_Req.io_Error = 0; u->preq.ios2_WireError = 0;
    }
    if (cmd == S2_GETSTATIONADDRESS && !err && is_bcast_or_zero(u->preq.ios2_SrcAddr)) cp(u->preq.ios2_SrcAddr, u->preq.ios2_DstAddr, 6);
    req->ios2_Req.io_Error = (BYTE)err; req->ios2_WireError = u->preq.ios2_WireError; req->ios2_PacketType = u->preq.ios2_PacketType;
    cp(req->ios2_SrcAddr, u->preq.ios2_SrcAddr, 16); cp(req->ios2_DstAddr, u->preq.ios2_DstAddr, 16);
    req->ios2_DataLength = u->preq.ios2_DataLength;
    if (!(req->ios2_Req.io_Flags & IOF_QUICK)) ReplyMsg(&req->ios2_Req.io_Message);
}

LONG fix_abortio(__reg("a6") struct Library *dev, __reg("a1") struct IOSana2Req *req)
{
    (void)dev; (void)req;
    return 0;                       /* control commands complete synchronously; data requests are the driver's */
}
