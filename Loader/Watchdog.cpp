#include <Windows.h>
#include "Watchdog.h"

BOOL Watchdog::DelayExecution_WFSO(FLOAT ftMinutes) {

	// Fast Forward detection technique:

	DWORD dwMilliSeconds	= ftMinutes * 60000;
	HANDLE hEvent			= CreateEvent(NULL, NULL, NULL, NULL);
	DWORD _T0				= NULL;
	DWORD _T1				= NULL;

	_T0 = GetTickCount64();

	if (WaitForSingleObject(hEvent, dwMilliSeconds) == WAIT_FAILED) {
		return FALSE;
	}

	_T1 = GetTickCount64();

	DWORD T1 = GetTickCount64();
	if ((DWORD)(_T1 - _T0) < dwMilliSeconds)
		return FALSE;

	CloseHandle(hEvent);
	return TRUE;
}