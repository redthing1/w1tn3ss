#pragma once

#include <windows.h>

// Define NTSTATUS if not already defined
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

/**
 * some windows api function pointers for "less documented" functions
 */

struct NtCreateThreadExBuffer {
  ULONG Size;
  ULONG Unknown1;
  ULONG Unknown2;
  PULONG Unknown3;
  ULONG Unknown4;
  ULONG Unknown5;
  ULONG Unknown6;
  PULONG Unknown7;
  ULONG Unknown8;
};

typedef NTSTATUS (WINAPI* LPFUN_NtCreateThreadEx)(
    PHANDLE hThread, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, ULONG StackZeroBits,
    ULONG SizeOfStackCommit, ULONG SizeOfStackReserve, LPVOID lpBytesBuffer
);
// Function Pointer Typedef for RtlCreateUserThread
typedef DWORD (WINAPI* pRtlCreateUserThread)(
    IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor, IN BOOL CreateSuspended,
    IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN LPVOID StartAddress,
    IN LPVOID StartParameter, OUT HANDLE ThreadHandle, OUT LPVOID ClientID
);
