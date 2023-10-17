#pragma once
#include <Windows.h>

class Watchdog {
public:
	BOOL DelayExecution_WFSO(FLOAT ftMinutes);
};