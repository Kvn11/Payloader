#pragma once
#include <Windows.h>

class Resolver {
public:
	FARPROC GetProcAddress(IN HMODULE hModule, IN LPCSTR lpApiName);

	HMODULE GetModHandle(IN LPCWSTR szModuleName);
};