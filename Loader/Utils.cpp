#include <Windows.h>
#include "Utils.h"

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {
	WCHAR lStr1[MAX_PATH];
	WCHAR lStr2[MAX_PATH];

	int len1 = lstrlenW(Str1);
	int len2 = lstrlenW(Str2);

	int i = 0;
	int j = 0;

	// Check Length:
	if (len1 >= MAX_PATH || len2 >= MAX_PATH) {
		return FALSE;
	}

	// COnvert str1 to lower case:
	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0';

	// COnvert str2 to lower case string:
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0';

	if (lstrcmpiW(lStr1, lStr2) == 0) {
		return TRUE;
	}
	return FALSE;
}

VOID AlertableFunction() {
	HANDLE	hEvent = CreateEvent(
		NULL,
		NULL,
		NULL,
		NULL
	);

	MsgWaitForMultipleObjectsEx(
		1,
		&hEvent,
		INFINITE,
		QS_HOTKEY,
		MWMO_ALERTABLE
	);
}