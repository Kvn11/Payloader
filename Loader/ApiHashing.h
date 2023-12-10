#pragma once

#include <Windows.h>

FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash);

HMODULE GetModuleHandleH(DWORD dwModuleNameHash);