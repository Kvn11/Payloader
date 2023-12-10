#pragma once
#include <Windows.h>
#include "Structs.h"
#include "Common.h"

BOOL WrapNtCreateUserProcess(
	IN PWSTR szTargetProcess,
	IN PWSTR szTargetProcessParameters,
	IN PWSTR szTargetProcessPath,
	OUT PHANDLE hProcess,
	OUT PHANDLE hThread
);

