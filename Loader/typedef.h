#pragma once

#include <Windows.h>
#include "Structs.h"

#ifndef TYPEDEF_H
#define TYPEDEF_H



// https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-gettickcount64
typedef ULONGLONG(WINAPI* fnGetTickCount64)();

typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx)(

	PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	PUNICODE_STRING					ImagePathName,
	PUNICODE_STRING					DllPath,
	PUNICODE_STRING					CurrentDirectory,
	PUNICODE_STRING					CommandLine,
	PVOID							Environment,
	PUNICODE_STRING					WindowTitle,
	PUNICODE_STRING					DesktopInfo,
	PUNICODE_STRING					ShellInfo,
	PUNICODE_STRING					RuntimeData,
	ULONG							Flags

	);

// https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpsapi.h#L2288

typedef NTSTATUS(NTAPI* fnNtCreateUserProcess)(

	PHANDLE							ProcessHandle,
	PHANDLE							ThreadHandle,
	ACCESS_MASK						ProcessDesiredAccess,
	ACCESS_MASK						ThreadDesiredAccess,
	POBJECT_ATTRIBUTES				ProcessObjectAttributes,
	POBJECT_ATTRIBUTES				ThreadObjectAttributes,
	ULONG							ProcessFlags,
	ULONG							ThreadFlags,
	PRTL_USER_PROCESS_PARAMETERS	ProcessParameters,
	PPS_CREATE_INFO					CreateInfo,
	PPS_ATTRIBUTE_LIST				pAttributeList

	);

// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
	
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect
	
	);

// https://web.archive.org/web/20210622011158/http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(

	HANDLE	ProcessHandle,
	PVOID*	BaseAddress,
	PULONG	NumberOfBytesToProtect,
	ULONG	NewAcceessProtection,
	PULONG	OldAccessProtection
	
	);

// https://web.archive.org/web/20220211135133/https://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	HANDLE	ProcessHandle,
	PVOID*	BaseAddress,
	PULONG	NumberOfBytesToProtect,
	ULONG	NewAccessProtection,
	PULONG	OldAccessProtection
	);

#endif // !TYPEDEF_H