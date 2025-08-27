#pragma once

// This file needs raw Windows headers for API definitions
// It should only be included by inject.hpp which isolates the pollution
#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

// define NTSTATUS if not already defined
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

typedef NTSTATUS(WINAPI* LPFUN_NtCreateThreadEx)(
    PHANDLE hThread, ACCESS_MASK DesiredAccess, LPVOID ObjectAttributes, HANDLE ProcessHandle,
    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, BOOL CreateSuspended, ULONG StackZeroBits,
    ULONG SizeOfStackCommit, ULONG SizeOfStackReserve, LPVOID lpBytesBuffer
);
// function Pointer Typedef for RtlCreateUserThread
typedef DWORD(WINAPI* pRtlCreateUserThread)(
    HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor, BOOL CreateSuspended, ULONG StackZeroBits,
    PULONG StackReserved, PULONG StackCommit, LPVOID StartAddress, LPVOID StartParameter, HANDLE ThreadHandle,
    LPVOID ClientID
);
