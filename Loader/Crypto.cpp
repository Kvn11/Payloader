#include "Crypto.h"
#include <Windows.h>

VOID Crypto::XorByOneKey(IN PBYTE pShellCode, IN SIZE_T sShellCodeSize, IN BYTE bKey) {
	for (size_t i = 0; i < sShellCodeSize; i++) {
		pShellCode[i] = pShellCode[i] ^ bKey;
	}
}