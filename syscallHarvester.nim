## WARNING: --opt:speed breaks it!
import winim
import hmatching

{.passC: "-masm=intel".}

const bytesFromFunction = 20 # how many bytes should be searched for the syscall

proc getSyscall(dll: HMODULE, procname: string): int16 =
  ## searches for the syscall of the given function.
  ## returns -1 if the syscall was not found
  var pntCreateThread: pointer = dll.GetProcAddress(procname)
  var antCreateThread: ptr array[20, byte] = cast[ptr array[20, byte]](pntCreateThread)
  for idx in 0 ..< bytesFromFunction:
    if idx + 6 > bytesFromFunction:
      return -1
    let cur = antCreateThread[idx].byte
    let six = @[
      antCreateThread[idx + 0].byte,
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


var ntdll = LoadLibrary("ntdll.dll")

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

{.push stackTrace: off.}
proc SyscallNtOpenProcess*(ProcessHandle: PHANDLE, AccessMask: ACCESS_MASK,
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
proc SyscallNtAllocateVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID,
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
proc SyscallNtWriteVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID,
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
proc SyscallNtCreateThread(
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


when isMainModule:
  import print
  import osproc, os

  print ntdll.getSyscall("NtOpenProcess").toHex()
  print ntdll.getSyscall("NtAllocateVirtualMemory").toHex()
  print ntdll.getSyscall("NtWriteVirtualMemory").toHex()
  print ntdll.getSyscall("NtCreateThreadEx").toHex()
  print ntdll.getSyscall("NtClose").toHex()
  print ntdll.getSyscall("NtCreateThread").toHex()
  print ntdll.getSyscall("NtOpenFile").toHex()
  print ntdll.getSyscall("NtProtectVirtualMemory").toHex()

  let tProcess = startProcess("notepad.exe")
  tProcess.suspend() # That's handy!
  var cid: CLIENT_ID
  var oa: OBJECT_ATTRIBUTES
  var pHandle: HANDLE

  cid.UniqueProcess = tProcess.processID

  var status = SyscallNtOpenProcess(
      &pHandle,
      PROCESS_ALL_ACCESS,
      &oa, &cid
  )
  echo status
  echo "[*] pHandle: ", pHandle
