#pragma once
#include <Windows.h>

class Crypto {
public:
	VOID XorByOneKey(IN PBYTE pShellCode, IN SIZE_T sShellcodeSize, IN BYTE bKey);
};