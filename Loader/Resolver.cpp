#include "Structs.h"
#include "Utils.h"
#include <winternl.h>
#include <Windows.h>
#include "Resolver.h"

FARPROC Resolver::GetProcAddress(IN HMODULE hModule, IN LPCSTR lpApiName) {
	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return nullptr;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		return nullptr;
	}

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting Image Export Table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD dwImgExportDirSize = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));
	PIMAGE_SECTION_HEADER pTextSectionHdr = nullptr;
	const char pTextSectionName[] = ".text\0";
	for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
		if (strcmp(pTextSectionName, (const char*)pImgSectionHdr->Name) == 0) {
			pTextSectionHdr = pImgSectionHdr;
			break;
		}
		pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	}

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (strcmp(lpApiName, pFunctionName) == 0) {

			// Add functionality for forwarded functions:
			if (((ULONG_PTR)pFunctionAddress >= (ULONG_PTR)pImgExportDir) &&
				(ULONG_PTR)pFunctionAddress < ((ULONG_PTR)pImgExportDir + dwImgExportDirSize)) {

				CHAR ForwarderName[MAX_PATH] = { 0 };
				DWORD DotOffset = 0;
				PCHAR FunctionMod = nullptr;
				PCHAR FunctionName = nullptr;

				memcpy(ForwarderName, pFunctionAddress, strlen((PCHAR)pFunctionAddress));

				// Parse for module name:
				for (DWORD i = 0; i < strlen((PCHAR)ForwarderName); i++) {
					if (((PCHAR)ForwarderName)[i] == '.') {
						DotOffset = i;
						ForwarderName[i] = NULL;
						break;
					}
				}
				FunctionMod = ForwarderName;
				FunctionName = ForwarderName + DotOffset + 1;

				return this->GetProcAddress(LoadLibraryA(FunctionMod), FunctionName);
			}
			return (FARPROC)pFunctionAddress;
		}
	}
	return nullptr;
}

HMODULE Resolver::GetModHandle(IN LPCWSTR szModuleName) {
#ifdef _WIN64
	PPEB pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB pPeb = (PEB*)(__readfsdword(0x30));
#endif
	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);

	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {
		if (pDte->FullDllName.Length != NULL) {
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif
			}
		}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}
	return nullptr;
}