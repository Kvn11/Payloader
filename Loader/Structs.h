#pragma once
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI* fnNtAllocateVirtualMemory)(
	HANDLE							ProcessHandle,
	PVOID*							BaseAddress,
	ULONG_PTR						ZeroBits,
	PSIZE_T							RegionSize,
	ULONG							AllocationType,
	ULONG							Protect
	);

typedef NTSTATUS(NTAPI* fnNtProtectVirtualMemory)(
	HANDLE							ProcessHandle,
	PVOID*							BaseAddress,
	PSIZE_T							NumberOfBytesToProtect,
	ULONG							NewAccessProtection,
	PULONG							OldAccessProtection
	);

typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory)(
	HANDLE							ProcessHandle,
	PVOID							BaseAddress,
	PVOID							Buffer,
	ULONG							NumberOfBytesToWrite,
	PULONG							NumberOfBytesWritten
	);

//
//typedef struct _IO_STATUS_BLOCK {
//	union {
//		NTSTATUS Status;
//		PVOID Pointer;
//	};
//	ULONG_PTR Information;
//} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG Reserved
	);

typedef NTSTATUS(NTAPI* fnNtQueueApcThread)(
	HANDLE ThreadHandle,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcRoutineContext,
	PIO_STATUS_BLOCK ApcStatusBlock,
	ULONG ApcReserved
	);